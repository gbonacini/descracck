// -----------------------------------------------------------------
// descracker - brute forcer for legacy Unix DES based password hash
// Copyright (C) 2008-2024  Gabriele Bonacini
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
// 
// CREDITS: DES impementation extracted from OpenSSL library 
//          All credits to original authors.
// -----------------------------------------------------------------

#include <iostream>
#include <fstream>
#include <algorithm>
#include <filesystem>

#include <cuda/semaphore>

#include "descuda.hpp"

namespace descrack {

using std::cout,
      std::cerr,
      std::string,
      std::abort,
      std::fill_n,
      std::copy_n,
      std::ifstream,
      std::filesystem::is_regular_file,
      cuda::binary_semaphore;

using DES_LONG=unsigned int;
using DES_cblock=unsigned char;

struct DES_cuda_ks {
    union {
        DES_cblock cblock[8]; 
        DES_LONG deslong[2];
    } ks[16];
};
using DES_key_schedule_cuda=DES_cuda_ks;

#define l2c(l,c)       (*((c)++)=(unsigned char)(((l)     )&0xff), \
                        *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                        *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                        *((c)++)=(unsigned char)(((l)>>24L)&0xff))

#define D_ENCRYPT(LL,R,S) { \
        LOAD_DATA_tmp(R,S,u,t,E0,E1); \
        t=ROTATE(t,4); \
        LL^= \
            DES_SPtrans[0][(u>> 2L)&0x3f]^ \
            DES_SPtrans[2][(u>>10L)&0x3f]^ \
            DES_SPtrans[4][(u>>18L)&0x3f]^ \
            DES_SPtrans[6][(u>>26L)&0x3f]^ \
            DES_SPtrans[1][(t>> 2L)&0x3f]^ \
            DES_SPtrans[3][(t>>10L)&0x3f]^ \
            DES_SPtrans[5][(t>>18L)&0x3f]^ \
            DES_SPtrans[7][(t>>26L)&0x3f]; }

#define ROTATE(a,n)     (((a)>>(n))+((a)<<(32-(n))))

#define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)),\
        (b)^=(t),\
        (a)^=((t)<<(n)))

#define LOAD_DATA_tmp(R,S,u,t,E0,E1) \
        { DES_LONG tmp; LOAD_DATA(R,S,u,t,E0,E1,tmp); }

#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
        t=R^(R>>16L); \
        u=t&E0; t&=E1; \
        tmp=(u<<16); u^=R^s[S  ]; u^=tmp; \
        tmp=(t<<16); t^=R^s[S+1]; t^=tmp

#define HPERM_OP(a,t,n,m) ((t)=((((a)<<(16-(n)))^(a))&(m)),\
        (a)=(a)^(t)^(t>>(16-(n))))

#define c2l(c,l)       (l =((DES_LONG)(*((c)++)))     , \
                        l|=((DES_LONG)(*((c)++)))<< 8L, \
                        l|=((DES_LONG)(*((c)++)))<<16L, \
                        l|=((DES_LONG)(*((c)++)))<<24L)

__device__ void DES_hash_cuda(const char *buf, const char *salt, char *ret) { // ret point to a char[14]
    unsigned int          x, y;
    DES_LONG              Eswap0, Eswap1, out[2], ll;
    DES_cblock            key[8];
    DES_key_schedule_cuda ks;
    unsigned char         bb[9], *b = bb, c, u;

    #include "desdata.h"

    x = ret[0] = salt[0];
    if (x == 0 || x >= sizeof(con_salt))
        return;
    Eswap0 = con_salt[x] << 2;
    x = ret[1] = salt[1];
    if (x == 0 || x >= sizeof(con_salt))
        return;
    Eswap1 = con_salt[x] << 6;

    key[0] = 0; key[1] = 0; key[2] = 0; key[3] = 0; key[4] = 0; key[5] = 0; key[6] = 0; key[7] = 0;
    int calc = 1;
    if(calc){ c = *(buf++); if(c){ key[0] = (c << 1); } else { calc = 0;}; }
    if(calc){ c = *(buf++); if(c){ key[1] = (c << 1); } else { calc = 0;}; }
    if(calc){ c = *(buf++); if(c){ key[2] = (c << 1); } else { calc = 0;}; }
    if(calc){ c = *(buf++); if(c){ key[3] = (c << 1); } else { calc = 0;}; }
    if(calc){ c = *(buf++); if(c){ key[4] = (c << 1); } else { calc = 0;}; }
    if(calc){ c = *(buf++); if(c){ key[5] = (c << 1); } else { calc = 0;}; }
    if(calc){ c = *(buf++); if(c){ key[6] = (c << 1); } else { calc = 0;}; }
    if(calc){ c = *(buf++); if(c){ key[7] = (c << 1); } else { calc = 0;}; }

    static const int    shifts2[16] = { 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0 };
    DES_LONG            cc, d, t, s, t2, *k = (DES_LONG*)&ks.ks[0];
    const unsigned char *in = &key[0];

    c2l(in, cc);
    c2l(in, d);

    PERM_OP(d, cc, t, 4, 0x0f0f0f0fL);
    HPERM_OP(cc, t, -2, 0xcccc0000L);
    HPERM_OP(d, t, -2, 0xcccc0000L);
    PERM_OP(d, cc, t, 1, 0x55555555L);
    PERM_OP(cc, d, t, 8, 0x00ff00ffL);
    PERM_OP(d, cc, t, 1, 0x55555555L);
    d = (((d & 0x000000ffL) << 16L) | (d & 0x0000ff00L) |
         ((d & 0x00ff0000L) >> 16L) | ((cc & 0xf0000000L) >> 4L));
    cc &= 0x0fffffffL;

    /* 1 */ if(shifts2[0]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else { cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL;
    *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L));
    *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 2 */ if(shifts2[1]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else { cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL;
    *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L));
    *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 3 */ if(shifts2[2]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else { cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL;
    *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L));
    *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 4 */ if(shifts2[3]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else { cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 5 */ if(shifts2[4]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else { cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 6 */ if(shifts2[5]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else { cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 7 */ if(shifts2[6]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else { cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 8 */ if(shifts2[7]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else { cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 9 */ if(shifts2[8]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else { cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 10 */ if(shifts2[9]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else { cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 11 */ if(shifts2[10]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else{ cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 12 */ if(shifts2[11]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else{ cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 13 */ if(shifts2[12]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else{ cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 14 */ if(shifts2[13]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else{ cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 15 */ if(shifts2[14]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else{ cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    /* 16 */ if(shifts2[15]){ cc = ((cc >> 2L) | (cc << 26L)); d = ((d >> 2L) | (d << 26L)); } else{ cc = ((cc >> 1L) | (cc << 27L)); d = ((d >> 1L) | (d << 27L));}
    cc &= 0x0fffffffL;
    d &= 0x0fffffffL;
    s = des_skb[0][(cc) & 0x3f] | des_skb[1][((cc >> 6L) & 0x03) | ((cc >> 7L) & 0x3c)] | des_skb[2][((cc >> 13L) & 0x0f) | 
	((cc >> 14L) & 0x30)] | des_skb[3][((cc >> 20L) & 0x01) | ((cc >> 21L) & 0x06) | ((cc >> 22L) & 0x38)];
    t = des_skb[4][(d) & 0x3f] | des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] | des_skb[6][(d >> 15L) & 0x3f] | 
	des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];
    t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL; *(k++) = ROTATE(t2, 30) & 0xffffffffL;
    t2 = ((s >> 16L) | (t & 0xffff0000L)); *(k++) = ROTATE(t2, 26) & 0xffffffffL;

  { 
        DES_LONG l = 0, r = 0, t, u, *s = (DES_LONG *)&ks, E0 = Eswap0, E1 = Eswap1;

        /* 1 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 2 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 3 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 4 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 5 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 6 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 7 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 8 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 9 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 10 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 11 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 12 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 13 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 14 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 15 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 16 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 17 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 18 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 19 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 20 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 21 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 22 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 23 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 24 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;
        /* 25 */ D_ENCRYPT(l, r, 0);  D_ENCRYPT(r, l, 2); D_ENCRYPT(l, r, 4); D_ENCRYPT(r, l, 6); D_ENCRYPT(l, r, 8); D_ENCRYPT(r, l, 10); 
	D_ENCRYPT(l, r, 12); D_ENCRYPT(r, l, 14); D_ENCRYPT(l, r, 16); D_ENCRYPT(r, l, 18); D_ENCRYPT(l, r, 20); D_ENCRYPT(r, l, 22); 
	D_ENCRYPT(l, r, 24); D_ENCRYPT(r, l, 26); D_ENCRYPT(l, r, 28); D_ENCRYPT(r, l, 30); t = l; l = r; r = t;

        l = ROTATE(l, 3) & 0xffffffffL;
        r = ROTATE(r, 3) & 0xffffffffL;

        PERM_OP(l, r, t,  1, 0x55555555L);
        PERM_OP(r, l, t,  8, 0x00ff00ffL);
        PERM_OP(l, r, t,  2, 0x33333333L);
        PERM_OP(r, l, t, 16, 0x0000ffffL);
        PERM_OP(l, r, t,  4, 0x0f0f0f0fL);
    
        out[0] = r;
        out[1] = l;
  } 

    ll = out[0];
    l2c(ll, b);
    ll = out[1];
    l2c(ll, b);
    y = 0;
    u = 0x80;
    bb[8] = 0;

    /*2*/ c = 0;
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    ret[2] = cov_2char[c];
    /*3*/ c = 0;
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    ret[3] = cov_2char[c];
    /*4*/ c = 0;
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    ret[4] = cov_2char[c];
    /*5*/ c = 0;
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    ret[5] = cov_2char[c];
    /*6*/ c = 0;
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    ret[6] = cov_2char[c];
    /*7*/ c = 0;
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    ret[7] = cov_2char[c];
    /*8*/ c = 0;
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    ret[8] = cov_2char[c];
    /*9*/ c = 0;
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    ret[9] = cov_2char[c];
    /*10*/ c = 0;
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    ret[10] = cov_2char[c];
    /*11*/ c = 0;
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    ret[11] = cov_2char[c];
    /*12*/ c = 0;
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    c <<= 1; if (bb[y] & u) c |= 1; u >>= 1; if (!u) { y++; u = 0x80; }
    ret[12] = cov_2char[c];
    
    ret[13] = '\0';
}

__device__ binary_semaphore<cuda::thread_scope_device> resultSem(1);

__global__ void crackDes(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize];
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      DES_hash_cuda(dict + (idx * DesCrack::passwordSize ), salt, out);
      if( hash[0] == out[0] && hash[1] == out[1] && hash[2] == out[2] && hash[3] == out[3] && hash[4] == out[4] && 
	      hash[5] == out[5] && hash[6] == out[6] && hash[7] == out[7] && hash[8] == out[8] && hash[9] == out[9] && 
	      hash[10] == out[10] && hash[11] == out[11] && hash[12] == out[12] ){

	              resultSem.acquire();
                  result[0] = *(dict + (idx * DesCrack::passwordSize ) );
                  result[1] = *(dict + (idx * DesCrack::passwordSize ) + 1 );
                  result[2] = *(dict + (idx * DesCrack::passwordSize ) + 2 );
                  result[3] = *(dict + (idx * DesCrack::passwordSize ) + 3 );
                  result[4] = *(dict + (idx * DesCrack::passwordSize ) + 4 );
                  result[5] = *(dict + (idx * DesCrack::passwordSize ) + 5 );
                  result[6] = *(dict + (idx * DesCrack::passwordSize ) + 6 );
                  result[7] = *(dict + (idx * DesCrack::passwordSize ) + 7 );
                  result[8] = *(dict + (idx * DesCrack::passwordSize ) + 8 );
                  __threadfence();
	              resultSem.release();
      }
   }
}

#define CHECK  auto  check { [&]() -> bool{ \
                   DES_hash_cuda(transformed, salt, out); \
                   if( hash[0] == out[0] && hash[1] == out[1] && hash[2] == out[2] && hash[3] == out[3] && hash[4] == out[4] &&  \
	                   hash[5] == out[5] && hash[6] == out[6] && hash[7] == out[7] && hash[8] == out[8] && hash[9] == out[9] &&  \
	                   hash[10] == out[10] && hash[11] == out[11] && hash[12] == out[12] ){ \
 \
	                           resultSem.acquire(); \
                               result[0] = *(transformed  ); \
                               result[1] = *(transformed  + 1 ); \
                               result[2] = *(transformed  + 2 ); \
                               result[3] = *(transformed  + 3 ); \
                               result[4] = *(transformed  + 4 ); \
                               result[5] = *(transformed  + 5 ); \
                               result[6] = *(transformed  + 6 ); \
                               result[7] = *(transformed  + 7 ); \
                               result[8] = *(transformed  + 8 ); \
                               __threadfence(); \
	                           resultSem.release(); \
                               return true; \
                   } \
                   return false; \
               } \
   }

   #define RESETFROM auto resetFrom  { [&](int start, const char* word){ \
                               transformed[0] = word[0]; \
                               transformed[1] = word[1]; \
                               transformed[2] = word[2]; \
                               transformed[3] = word[3]; \
                               transformed[4] = word[4]; \
                               transformed[5] = word[5]; \
                               transformed[6] = word[6]; \
                               transformed[7] = word[7]; \
                   } \
   }

   #define RESETFROMCASETOGGLED auto resetFromCaseToggled  { [&](int start, const char* word){ \
                          for(int idx{start}; idx < DesCrack::passwordSize - 1; idx++) {\
                                if(word[idx] >= 0x61 && word[idx] <= 0x7A ){ \
                                       transformed[idx] = word[idx] - 0x20; \
                                       if(check()) return; \
                                }else if(word[idx] >= 0x41 && word[idx] <= 0x5A ){ \
                                       transformed[idx] = word[idx] + 0x20; \
                                       if(check()) return; \
                                } \
                            } \
                   } \
   }

   #define RESETSHIFT2 auto resetShift2{ [&](const char* word){ \
                               transformed[0] = 0; \
                               transformed[1] = 0; \
                               transformed[2] = word[0]; \
                               transformed[3] = word[1]; \
                               transformed[4] = word[2]; \
                               transformed[5] = word[3]; \
                               transformed[6] = word[4]; \
                               transformed[7] = word[5]; \
                   } \
   }

   #define RESETSHIFT1 auto resetShift1{ [&](const char* word){ \
                               transformed[0] = 0; \
                               transformed[1] = word[0]; \
                               transformed[2] = word[1]; \
                               transformed[3] = word[2]; \
                               transformed[4] = word[3]; \
                               transformed[5] = word[4]; \
                               transformed[6] = word[5]; \
                               transformed[7] = word[6]; \
                   } \
   }

   #define WORDSIZE auto wordSize  { [&](const char* word) -> size_t { \
                          if(word[0] == 0 ) return 0; \
                          if(word[1] == 0 ) return 1; \
                          if(word[2] == 0 ) return 2; \
                          if(word[3] == 0 ) return 3; \
                          if(word[4] == 0 ) return 4; \
                          if(word[5] == 0 ) return 5; \
                          if(word[6] == 0 ) return 6; \
                          if(word[7] == 0 ) return 7; \
                          if(word[8] == 0 ) return 8; \
                          return 0; \
                   } \
   }

   #define RESETFROMREVERSED auto resetFromReversed  { [&](const char* word){ \
                               for(int idx{DesCrack::passwordSize - 1}, didx{0}; idx > -1; idx--) \
                                   if(word[idx] != 0) { \
                                        transformed[didx] = word[idx]; \
                                        didx++; \
                                   } \
                   } \
   }

   #define ADDNUMBERS auto addNumbers { [&](size_t idx1) -> bool { \
                          size_t idx2 = idx1 + 1; \
                          for(int i{0}; i<10 ; i++) \
                             for(int j{0}; j<10 ; j++){ \
                                 transformed[idx1] = 0x30 + i ; \
                                 transformed[idx2] = 0x30 + j ; \
                                 if(check()) return true; \
                             } \
                           if(transformed[0] >= 0x61 && transformed[0] <= 0x7A ){ \
                                 transformed[0] = transformed[0] - 0x20; \
                                 for(int i{0}; i<10 ; i++) \
                                    for(int j{0}; j<10 ; j++){ \
                                        transformed[idx1] = 0x30 + i ; \
                                        transformed[idx2] = 0x30 + j ; \
                                        if(check()) return true; \
                                    } \
                           } \
                           return false; \
                    } \
   }

   #define ADDSINGLENUMBER auto addSingleNumber { [&](size_t idx1) -> bool { \
                          for(int i{0}; i<10 ; i++) { \
                              transformed[idx1] = 0x30 + i ; \
                              if(check()) return true; \
                          } \
                          if(transformed[0] >= 0x61 && transformed[0] <= 0x7A ) {\
                                transformed[0] = transformed[0] - 0x20; \
                                for(int i{0}; i<10 ; i++) { \
                                    transformed[idx1] = 0x30 + i ; \
                                    if(check()) return true; \
                                } \
                          } \
                          return false; \
                    } \
   }

   #define ADDSINGLESPECIAL auto addSingleSpecial { [&](size_t idx1) -> bool { \
                          const char spec[] =  {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28, \
                                                0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x3A,0x3B, \
                                                0x3C,0x3D,0x3E,0x3F,0x40,0x5B,0x5C,0x5D,0x5E, \
                                                0x5F,0x60,0x7B,0x7C,0x7D,0x7E}; \
                          transformed[idx1 + 1 ] = 0; \
                          for(int i{0}; i<sizeof(spec) ; i++) {\
                              transformed[idx1] = spec[i] ; \
                              if(check()) return true; \
                          } \
                          if(transformed[0] >= 0x61 && transformed[0] <= 0x7A ){ \
                                transformed[0] = transformed[0] - 0x20; \
                                for(int i{0}; i<sizeof(spec) ; i++) {\
                                    transformed[idx1] = spec[i] ; \
                                    if(check()) return true; \
                                } \
                          } \
                          return false; \
                    } \
   }

   #define ADDFRONTSINGLESPECIAL auto addFrontSingleSpecial { [&]() -> bool { \
                          const char spec[] =  {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28, \
                                                0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x3A,0x3B, \
                                                0x3C,0x3D,0x3E,0x3F,0x40,0x5B,0x5C,0x5D,0x5E, \
                                                0x5F,0x60,0x7B,0x7C,0x7D,0x7E}; \
                          for(int i{0}; i<sizeof(spec) ; i++) { \
                              transformed[0] = spec[i] ; \
                              if(check()) return true; \
                          } \
                          if(transformed[1] >= 0x61 && transformed[1] <= 0x7A ){ \
                                   transformed[1] = transformed[1] - 0x20; \
                                   for(int i{0}; i<sizeof(spec) ; i++) { \
                                       transformed[0] = spec[i] ; \
                                       if(check()) return true; \
                                   } \
                          } \
                          return false; \
                    } \
   }

   #define ADDNUMBERSFRONT auto addNumbersFront { [&]() -> bool { \
                          for(int i{0}; i<10 ; i++) \
                             for(int j{0}; j<10 ; j++){ \
                                 transformed[0] = 0x30 + i ; \
                                 transformed[1] = 0x30 + j ; \
                                 if(check()) return true; \
                             } \
                           if(transformed[2] >= 0x61 && transformed[2] <= 0x7A ) \
                                transformed[2] = transformed[2] - 0x20; \
                           for(int i{0}; i<10 ; i++) \
                             for(int j{0}; j<10 ; j++){ \
                                 transformed[0] = 0x30 + i ; \
                                 transformed[1] = 0x30 + j ; \
                                 if(check()) return true; \
                             } \
                           return false; \
                    } \
   }

   #define LEET2 auto leet2 { [&](char ch) -> char { \
                               switch(ch){ \
                                   case 'A': \
                                   case 'a': \
                                      return '4'; \
                                   case 'E': \
                                   case 'e': \
                                      return '3'; \
                                   case 'I': \
                                   case 'i': \
                                      return '1'; \
                                   case 'O': \
                                   case 'o': \
                                      return '0'; \
                                   case 'S': \
                                   case 's': \
                                      return '5'; \
                                   case 'T': \
                                   case 't': \
                                      return '7'; \
                                   case 'Z': \
                                   case 'z': \
                                      return '2'; \
                                   default: \
                                      return '\0'; \
                               } \
                            } \
    }

   #define LEET auto leet { [&](char ch) -> char { \
                               switch(ch){ \
                                   case 'A': \
                                   case 'a': \
                                      return '4'; \
                                   case 'E': \
                                   case 'e': \
                                      return '3'; \
                                   case 'I': \
                                   case 'i': \
                                      return '1'; \
                                   case 'O': \
                                   case 'o': \
                                      return '0'; \
                                   default: \
                                      return '\0'; \
                               } \
                            } \
    }

   #define ADDSINGLENUMBERFRONT auto addSingleNumberFront { [&]() -> bool { \
                          for(int i{0}; i<10 ; i++) { \
                                 transformed[0] = 0x30 + i ; \
                                 if(check()) return true; \
                           } \
                           if(transformed[1] >= 0x61 && transformed[1] <= 0x7A ) { \
                                transformed[1] = transformed[1] - 0x20; \
                                for(int i{0}; i<10 ; i++) { \
                                      transformed[0] = 0x30 + i ; \
                                      if(check()) return true; \
                                 } \
                           } \
                           return false; \
                    } \
   }

__global__ void crackDesTr1_1(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETFROM;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char* word = dict + (idx * DesCrack::passwordSize );
      resetFrom(0, word);
      if(word[0] >= 0x61 && word[0] <= 0x7A ){
             transformed[0] = word[0] - 0x20;
             if(check()) return;
      }
    }
}

__global__ void crackDesTr1_2(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETFROM;
   ADDSINGLENUMBER;
   WORDSIZE;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char* word = dict + (idx * DesCrack::passwordSize );
      size_t           len = wordSize(word);
      resetFrom(0, word);
      switch(len){
              case 1:
              case 2:
              case 3:
              case 4:
              case 5:
              case 6:
              case 7:
                  if(addSingleNumber(len)) return;
              break;
              case 8:
                  if(addSingleNumber(7)) return;
      }
   }
}

__global__ void crackDesTr1_3(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETFROM;
   ADDNUMBERS;
   WORDSIZE;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char* word = dict + (idx * DesCrack::passwordSize );
      size_t      len  = wordSize(word);
      resetFrom(0, word);
      switch(len){
              case 1:
              case 2:
              case 3:
              case 4:
              case 5:
              case 6:
                  if(addNumbers(len)) return;
              break;
              case 7:
              case 8:
                  if(addNumbers(6)) return;
      }
   }
}

__global__ void crackDesTr1_4(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETFROM;
   ADDSINGLESPECIAL;
   ADDFRONTSINGLESPECIAL;
   RESETSHIFT1;
   WORDSIZE;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char*      word = dict + (idx * DesCrack::passwordSize );
      size_t           len  = wordSize(word);
      resetFrom(0, word);
      switch(len){
              case 1:
              case 2:
              case 3:
              case 4:
              case 5:
              case 6:
              case 7:
                  if(addSingleSpecial(len)) return;
              break;
              case 8:
                  if(addSingleSpecial(7)) return;
      }
      resetShift1(word);
      if(addFrontSingleSpecial()) return;
   }
}

__global__ void crackDesTr1_5(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETFROM;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char* word = dict + (idx * DesCrack::passwordSize );
      resetFrom(0, word);
      for(int idx{0}; idx < DesCrack::passwordSize - 1; idx++){
          if(word[idx] >= 0x61 && word[idx] <= 0x7A ){
             transformed[idx] = word[idx] - 0x20;
             if(check()) return;
          }
      }
      resetFrom(0, word);
      if(word[0] >= 0x61 && word[0] <= 0x7A ) transformed[0] = word[0] - 0x20;
      if(word[2] >= 0x61 && word[2] <= 0x7A ) transformed[2] = word[2] - 0x20;
      if(word[4] >= 0x61 && word[4] <= 0x7A ) transformed[4] = word[4] - 0x20;
      if(word[6] >= 0x61 && word[6] <= 0x7A ) transformed[6] = word[6] - 0x20;
      if(check()) return;
      resetFrom(0, word);
      if(word[1] >= 0x61 && word[1] <= 0x7A ) transformed[1] = word[1] - 0x20;
      if(word[3] >= 0x61 && word[3] <= 0x7A ) transformed[3] = word[3] - 0x20;
      if(word[5] >= 0x61 && word[5] <= 0x7A ) transformed[5] = word[5] - 0x20;
      if(word[7] >= 0x61 && word[7] <= 0x7A ) transformed[7] = word[7] - 0x20;
      if(check()) return;
      resetFrom(0, word);
      if(word[0] >= 0x61 && word[0] <= 0x7A ) transformed[0] = word[0] - 0x20;
      if(word[3] >= 0x61 && word[3] <= 0x7A ) transformed[3] = word[3] - 0x20;
      if(word[6] >= 0x61 && word[6] <= 0x7A ) transformed[6] = word[6] - 0x20;
      if(check()) return;
      resetFrom(0, word);
      if(word[0] >= 0x61 && word[0] <= 0x7A ) transformed[0] = word[0] - 0x20;
      if(word[7] >= 0x61 && word[7] <= 0x7A ) transformed[7] = word[7] - 0x20;
      if(check()) return;
    }
}

__global__ void crackDesTr1_6(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETSHIFT1;
   RESETSHIFT2;
   ADDSINGLENUMBERFRONT;
   ADDNUMBERSFRONT;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char* word = dict + (idx * DesCrack::passwordSize );
      resetShift1(word);
      if(addSingleNumberFront()) return;
      resetShift2(word);
      if(addNumbersFront()) return;
   }
}

__global__ void crackDesTr2_1(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETFROMREVERSED;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char* word = dict + (idx * DesCrack::passwordSize );
      resetFromReversed(word);
      if(check()) return;
   }
}

__global__ void crackDesTr2_2(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETFROM;
   RESETFROMREVERSED;
   WORDSIZE;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char*      word = dict + (idx * DesCrack::passwordSize );
      resetFromReversed(word);
      if(check()) return;
      size_t           len = wordSize(word);
      resetFrom(0, word);
      switch(len){
              case 1:
                  transformed[1]=transformed[0];
                  if(check()) return;
              break;
              case 2:
                  transformed[2]=transformed[0];
                  transformed[3]=transformed[1];
                  if(check()) return;
                  transformed[2]=transformed[1];
                  transformed[3]=transformed[0];
                  if(check()) return;
              break;
              case 3:
                  transformed[3]=transformed[0];
                  transformed[4]=transformed[1];
                  transformed[5]=transformed[2];
                  if(check()) return;
                  transformed[3]=transformed[2];
                  transformed[4]=transformed[1];
                  transformed[5]=transformed[0];
                  if(check()) return;
              break;
              case 4:
                  transformed[4]=transformed[0];
                  transformed[5]=transformed[1];
                  transformed[6]=transformed[2];
                  transformed[7]=transformed[3];
                  if(check()) return;
                  transformed[4]=transformed[3];
                  transformed[5]=transformed[2];
                  transformed[6]=transformed[1];
                  transformed[7]=transformed[0];
                  if(check()) return;
              break;
              case 5:
                  transformed[5]=transformed[0];
                  transformed[6]=transformed[1];
                  transformed[7]=transformed[2];
                  if(check()) return;
              break;
              case 6:
                  transformed[6]=transformed[0];
                  transformed[7]=transformed[1];
                  if(check()) return;
              break;
              case 7:
                  transformed[7]=transformed[0];
                  if(check()) return;
              break;
              case 8:
              break;
      }
   }
}

__global__ void crackDesTr2_3(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETFROM;
   LEET;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char* word = dict + (idx * DesCrack::passwordSize );
      resetFrom(0, word);
      for(int idx{0}; idx < ( DesCrack::passwordSize - 1 ) && 
                              transformed[idx] !=0; idx++){
          char newch = leet(transformed[idx]);
          if(newch != 0 ){
             transformed[idx] = newch;
             if(check()) return;
          }
      }
    }
}

__global__ void crackDesTr2_4(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETFROM;
   LEET2;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char* word = dict + (idx * DesCrack::passwordSize );
      resetFrom(0, word);
      for(int idx{0}; idx < ( DesCrack::passwordSize - 1 ) && 
                              transformed[idx] !=0; idx++){
          char newch = leet2(transformed[idx]);
          if(newch != 0 ){
             transformed[idx] = newch;
             if(check()) return;
          }
      }
    }
}

__global__ void crackDesTr3_1(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETFROMCASETOGGLED;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char* word = dict + (idx * DesCrack::passwordSize );
      resetFromCaseToggled(0, word);
      if(check()) return;
    }
}

__global__ void crackDesTr3_2(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETSHIFT1;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char* word = dict + (idx * DesCrack::passwordSize );
      resetShift1(word);
      transformed[0] = transformed[1];
      if(check()) return;
      if(transformed[0] >= 0x61 && transformed[0] <= 0x7A ){
             transformed[0] = transformed[0] - 0x20;
             if(check()) return;
             transformed[1] = transformed[1] - 0x20;
             if(check()) return;
      }
    }
}

__global__ void crackDesTr3_3(const char* dict, size_t rows, const char* hash, char* result){
   char salt[DesCrack::saltSize],
        out[DesCrack::hashSize],
        transformed[DesCrack::passwordSize] = {};
   
   salt[0]=hash[0]; salt[1]=hash[1]; salt[2]=0;
   unsigned int cidx { blockIdx.x * blockDim.x + threadIdx.x },
                cblk { blockDim.x * gridDim.x };
   CHECK;
   RESETFROMREVERSED;
   WORDSIZE;

   for(size_t idx{cidx}; idx<rows; idx += cblk){
      if(result[0] != 0 ) return;
      const char* word = dict + (idx * DesCrack::passwordSize );
      resetFromReversed(word);
      if(check()) return;
      size_t           len = wordSize(word);
      switch(len){
              case 1:
                  transformed[0]=word[0];
                  transformed[1]=word[0];
              break;
              case 2:
                  transformed[0]=word[0];
                  transformed[1]=word[0];
                  transformed[2]=word[1];
                  transformed[3]=word[1];
              break;
              case 3:
                  transformed[0]=word[0];
                  transformed[1]=word[0];
                  transformed[2]=word[1];
                  transformed[3]=word[1];
                  transformed[4]=word[2];
                  transformed[5]=word[2];
              break;
              case 4:
              case 5:
              case 6:
              case 7:
              case 8:
                  transformed[0]=word[0];
                  transformed[1]=word[0];
                  transformed[2]=word[1];
                  transformed[3]=word[1];
                  transformed[4]=word[2];
                  transformed[5]=word[2];
                  transformed[6]=word[3];
                  transformed[7]=word[3];
              break;
      }
      if(check()) return;
   }
}

DesCrack::DesCrack(const string hash, bool  tMode)  noexcept 
      : transformMode { tMode }, 
        group1{
                 [&](size_t blks){crackTr1_1(blks);},
                 [&](size_t blks){crackTr1_6(blks);},
                 [&](size_t blks){crackTr1_2(blks);},
                 [&](size_t blks){crackTr1_4(blks);},
                 [&](size_t blks){crackTr1_5(blks);},
                 [&](size_t blks){crackTr1_3(blks);}
              },
        group2{
                 [&](size_t blks){crackTr2_1(blks);},
                 [&](size_t blks){crackTr2_2(blks);},
                 [&](size_t blks){crackTr2_3(blks);}, 
                 [&](size_t blks){crackTr2_4(blks);} 
              },
        group3{
                 [&](size_t blks){crackTr3_1(blks);},
                 [&](size_t blks){crackTr3_2(blks);},
                 [&](size_t blks){crackTr3_3(blks);}
              }

{
    int         cudaDetectedDevices  { 0 };
    cudaError_t errorId              { cudaGetDeviceCount(&cudaDetectedDevices) };
    if(errorId != cudaSuccess) {
	    cerr << "Error probing Cuda devices: " << errorId << " - " << cudaGetErrorString(errorId) << "\n";
	    abort();
    }

    if (cudaDetectedDevices == 0) {
	    cerr << "Error: No Cuda device found\n";
	    abort();
    }

    if(cudaMallocManaged(&password, passwordSize) != cudaSuccess){
	    cerr << "Error: allocating unified memory\n";
	    abort();
    }

    if(cudaMallocManaged(&hashTarget, hashSize)  != cudaSuccess){
	    cerr << "Error: allocating unified memory\n";
	    abort();
    }

    if(hash.size() != hashSize - 1){
	    cerr << "Error: invalid hash length\n";
	    abort();
    }

    fill_n(hashTarget, hashSize, 0);
    fill_n(password, passwordSize, 0);
    copy_n(hash.c_str(), hashSize-1, hashTarget);
}

DesCrack::~DesCrack(void)  noexcept{
	cudaFree(password);
	cudaFree(hashTarget);
	cudaFree(dict);
}

void DesCrack::crack(size_t blocks) noexcept{
   cout << "Dictionary attack started\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDes<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr1_1(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : initial-capital\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr1_1<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr1_2(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : append single digit, initial-capital + append digit\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr1_2<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr1_3(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : append single special character, initial-capital + append spec. character\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr1_3<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr1_4(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : append special character, initial-capital + special\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr1_4<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr1_5(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : some upper case combinations\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr1_5<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr1_6(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : add digit(s) at begining, initial-capital + digit(s) at beginning\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr1_6<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr2_1(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : reverse\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr2_1<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr2_2(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : specular, repeated\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr2_2<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr2_3(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : leet\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr2_3<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr2_4(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : leet extended\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr2_4<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr3_1(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : toggle upper/lower case \n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr3_1<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr3_2(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : Initial duplicated lower /upper case\n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr3_2<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

void DesCrack::crackTr3_3(size_t blocks) noexcept{
   cout << "Dictionary attack with transformation  : duplicated characters \n";
   int dim = (rows + blocks - 1) / blocks;
   crackDesTr3_3<<<dim, blocks>>>(dict, rows, hashTarget, password);
   cudaDeviceSynchronize();
   if(hasResult()) cout << "Password: " << password << '\n';
   else            cout << "No password found.\n";
}

size_t  DesCrack::countDictItems(void)  noexcept{
    if(! is_regular_file(dictFile)){
	    cerr << "Error: dictionary file wrong path or type.\n";
	    abort();
    }

    ifstream dictionary(dictFile);
    size_t   lines{0};
    for( string line; getline( dictionary, line ); lines++ ){}
    return lines;
}

void DesCrack::loadDict(std::string dFile) noexcept{
    dictFile = dFile;
    rows     = countDictItems();
	cudaFree(dict);
    if( cudaMallocManaged(&dict, rows * cols) != cudaSuccess){
	    cerr << "Error: allocating unified memory\n";
	    abort();
    }
    fill_n(dict, rows * cols, 0);
    ifstream dictionary(dictFile);
    size_t   lines{0};
    for( string line; getline( dictionary, line ); lines++ ){
        if(lines > rows - 1){
            cerr << "Error: dict file changed\n";
            abort();
        }

        for(int i{0}; i < (cols - 1) && i < line.size(); i++)
             *(dict + lines * cols + i ) = line[i];
    }

    cout << "Dictionary loaded: " << lines << " elements\n";
}

 bool DesCrack::hasResult(void)  noexcept{
    return password[0] != 0 ? true : false;
 }

 void  DesCrack::execGroups(size_t gr, size_t blocks) noexcept{
     cout << "Dictionary attack with transformation  : from  group 1 to " << gr << " \n";
     if(gr >= 1){
        for(auto member : group1)
            member(blocks);
        cout << "End group 1.\n";
     }
     if(gr >= 2){
        for(auto member : group2)
            member(blocks);
        cout << "End group 2.\n";
     }
     if(gr >= 3){
        for(auto member : group3)
            member(blocks);
        cout << "End group 3.\n";
     }
 }

 void  DesCrack::execGroup(size_t gr, size_t blocks) noexcept{
     cout << "Dictionary attack with transformation  : from  group " << gr << " \n";
     switch(gr){
         case 1:
            for(auto member : group1)
                member(blocks);
            cout << "End group 1.\n";
         break;
         case 2:
            for(auto member : group2)
                member(blocks);
            cout << "End group 2.\n";
         break;
         case 3:
            for(auto member : group3)
                member(blocks);
            cout << "End group 3.\n";
         break;
     }
 }
 
 } // End Namespace