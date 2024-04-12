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
// -----------------------------------------------------------------

#pragma once

#include <string>
#include <vector>
#include <functional>

namespace descrack {

using Group=std::vector<std::function<void(size_t blks)>>;
class DesCrack {
   private: 
     static inline  size_t       rows         { 0 };

     char                        *hashTarget   { nullptr };
     char                        *password     { nullptr }; 
     char                        *dict         { nullptr };
     std::string                 dictFile      {""};
     bool                        transformMode;
     Group                       group1,
                                 group2,
                                 group3;
     
     size_t   countDictItems(void)                                  noexcept;
     void     crackTr1_1(size_t blocks = 256 )                      noexcept;
     void     crackTr1_2(size_t blocks = 256 )                      noexcept;
     void     crackTr1_3(size_t blocks = 256 )                      noexcept;
     void     crackTr1_4(size_t blocks = 256 )                      noexcept;
     void     crackTr1_5(size_t blocks = 256 )                      noexcept;
     void     crackTr1_6(size_t blocks = 256 )                      noexcept;
     void     crackTr2_1(size_t blocks = 256 )                      noexcept;
     void     crackTr2_2(size_t blocks = 256 )                      noexcept;
     void     crackTr2_3(size_t blocks = 256 )                      noexcept;
     void     crackTr2_4(size_t blocks = 256 )                      noexcept;
     void     crackTr3_1(size_t blocks = 256 )                      noexcept;
     void     crackTr3_2(size_t blocks = 256 )                      noexcept;
     void     crackTr3_3(size_t blocks = 256 )                      noexcept;

     
   public:
     const static inline  size_t cols         { 9 },
                                 hashSize     { 14 },
                                 passwordSize { 9 },
                                 saltSize     { 3 };

     explicit DesCrack(const std::string hash,
                              bool  tMode=false)                    noexcept;
              ~DesCrack(void)                                       noexcept;
     void     crack(size_t blocks = 256 )                           noexcept;
     void     loadDict(std::string dFile)                           noexcept;
     bool     hasResult(void)                                       noexcept;
     void     execGroups(size_t gr, size_t blocks = 256)            noexcept;
     void     execGroup(size_t gr, size_t blocks = 256)             noexcept;

};

} // End Namespace
