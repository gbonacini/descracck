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

#include <iostream>
#include <unistd.h>
#include <string>

#include "parseCmdLine.hpp"
#include "descuda.hpp"

#ifdef __clang__
  void printInfo(char* cmd) __attribute__((noreturn));
#else
  [[ noreturn ]]
  void printInfo(char* cmd);
#endif

using std::cout,
      std::cerr,
      std::string,
      std::stoul,
      parcmdline::ParseCmdLine,
      descrack::DesCrack;

int main(int argc, char** argv){
  const char       flags[]         { "hH:d:b:t:T:" };
  string           hashString      { "" },
                   dictFile        { "" };
  size_t           bthreads        { 256 },
                   transformMode   { 0 };
  bool             multipleGroups  { false },
                   singleGroup     { false };

    
  ParseCmdLine  pcl{argc, argv, flags};
  if(pcl.getErrorState()){
        string exitMsg{string("Invalid  parameter or value").append(pcl.getErrorMsg())};
        cerr << exitMsg << "\n";
        printInfo(argv[0]);
  }
  if(pcl.isSet('t') && pcl.isSet('T')){
        cerr << "-t and -T are mutually exclusive\n";
        printInfo(argv[0]);
  }

  if(pcl.isSet('h'))
        printInfo(argv[0]);

  if(!pcl.isSet('H') ){
        cerr << "-H flag is mandatory" << "\n";
        printInfo(argv[0]);
  }

  if(!pcl.isSet('d') ){
        cerr << "-d flag is mandatory" << "\n";
        printInfo(argv[0]);
    }

  if(pcl.isSet('t') ){
     multipleGroups = true;
     transformMode = stoul(pcl.getValue('t'));
  }

  if(pcl.isSet('T') ){
     singleGroup = true;
     transformMode = stoul(pcl.getValue('T'));
  }

  if(pcl.isSet('b') ) bthreads      = stoul(pcl.getValue('b'));

  hashString = pcl.getValue('H');
  dictFile = pcl.getValue('d');

  DesCrack  tdc(hashString, transformMode);
  tdc.loadDict(dictFile);
  tdc.crack(bthreads);
  if(multipleGroups  && ! tdc.hasResult()) tdc.execGroups(transformMode, bthreads);
  if(singleGroup && ! tdc.hasResult()) tdc.execGroup(transformMode, bthreads);

  return 0;	
}

void printInfo(char* cmd){
      cerr << "\n" << cmd << " [-H<hash>] [-d dict_file] [ -t group | -T group ] | [-h]\n\n" 
           << " -H  <hash>      hash to crack\n" 
           << " -d  <dict_file> dictionary file\n" 
           << " -t  <1|2|3>     enable cascading transformation groups\n" 
           << " -T  <1|2|3>     enable specific transformation group\n" 
           << " -b  <units>     cuda block size (optional)\n" 
           << " -h              print this synopsis\n";
      exit(EXIT_FAILURE);
}