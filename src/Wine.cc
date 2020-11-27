/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <algorithm>
#include <cstdint>
#include <list>
#include <sstream>
#include <string>

#include "AddressSpace.h"
#include "Task.h"
#include "log.h"

using namespace std;

namespace rr {

/* see wine include/winnt.h*/
#define IMAGE_DOS_SIGNATURE    0x5A4D     /* MZ   */
#define IMAGE_NT_SIGNATURE     0x00004550 /* PE00 */
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
struct __attribute__((packed)) IMAGE_DOS_HEADER {
  uint16_t e_magic;  /* 00: MZ Header signature */
  char unused1[0x3a];
  uint32_t e_lfanew; /* 3c: Offset to extended header */
};
struct __attribute__((packed)) IMAGE_FILE_HEADER {
  char unused1[0x2];
  uint16_t NumberOfSections;
  char unused2[0xc];
  uint16_t SizeOfOptionalHeader;
  char unused3[0x2];
};
struct __attribute__((packed)) IMAGE_OPTIONAL_HEADER32 {
  uint16_t Magic;
  char unused1[0xde];
};
struct __attribute__((packed)) IMAGE_NT_HEADERS {
  uint32_t Signature;
  struct IMAGE_FILE_HEADER FileHeader;
  struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};
struct __attribute__((packed)) IMAGE_SECTION_HEADER {
  char unused1[0xc];
  uint32_t VirtualAddress;
  char unused2[0x18];
};
#define IMAGE_FIRST_SECTION(ntheader) \
  ((struct IMAGE_SECTION_HEADER*)((char *)&(ntheader)->OptionalHeader + \
                           (ntheader)->FileHeader.SizeOfOptionalHeader))


string create_library_response_from_mappings(Task *t) {

  // create an own list of the current mappings
  list<KernelMapping> mapping_list;
  for (KernelMapIterator it(t); !it.at_end(); ++it) {
    auto km = it.current();
    if (km.fsname().substr(0, 7) == "/memfd:")
      continue;
    if (km.is_vdso() || km.is_heap() || km.is_stack() || km.is_vvar() || km.is_vsyscall())
      continue;
    LOG(debug) << "Possible mapping for GDB reply: " << km;
    mapping_list.push_back(km);
  }

  struct library {
    library() : has_exec(false) {};
    vector<remote_ptr<void>> segments;
    bool has_exec;
  };
  map<string, library> libraries;

  // iterate through the mappings and search for PE libraries
  // see wine, packet_query_libraries_cb
  char buf[0x400];
  for (auto it = mapping_list.begin(); it != mapping_list.end(); it++) {
    auto km = *it;
    bool ok = true;
    t->read_bytes_helper(km.start(), sizeof(buf), buf, &ok);
    if (ok) {
      struct IMAGE_DOS_HEADER* dosheader = (struct IMAGE_DOS_HEADER*)buf;
      struct IMAGE_NT_HEADERS* ntheader = (struct IMAGE_NT_HEADERS*)(buf + dosheader->e_lfanew);
      if (dosheader->e_magic == IMAGE_DOS_SIGNATURE &&
          dosheader->e_lfanew < sizeof(buf)-4 &&
          ntheader->Signature == IMAGE_NT_SIGNATURE)
      {
        if (ntheader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
            ntheader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
          vector<remote_ptr<void>> segments;
          struct IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(ntheader);
          for (int i = 0; sec && i < std::max(ntheader->FileHeader.NumberOfSections, (uint16_t)1); ++i) {
            struct IMAGE_SECTION_HEADER* seci = sec + i;
            if ((char*)seci > buf + sizeof(buf)) break;
            segments.push_back(km.start() + seci->VirtualAddress);
          }

          string name = km.fsname();

          // If the mapping with the PE signature has no name assigned search the other segments for a name.
          for (auto it2 = mapping_list.begin(); name.empty() && it2 != mapping_list.end(); it2++) {
            if (find(segments.begin(), segments.end(), it2->start()) != segments.end()) {
              if (!it2->fsname().empty()) {
                name = it2->fsname();
              }
            }
          }

          // we found no name
          if (name.empty()) {
            continue;
          }

          // e.g. gdi32.so is prepared by wine to be found as PE image, but gdb does not like it.
          if (name.substr(name.length() - 3, 3) == ".so") {
            continue;
          }

          libraries[name].segments = segments;
          libraries[name].has_exec = true;
        }
      }
    }
  }

  // remove mappings related to PE libraries
  for (auto m = mapping_list.begin(); m != mapping_list.end(); ) {
    bool del = false;
    for (auto lib : libraries) {
      if (m->fsname() == lib.first) del = true;
      if (!del) {
        for (auto seg : lib.second.segments) {
          if (seg == m->start()) del = true;
        }
      }
    }
    if (del)
      m = mapping_list.erase(m);
    else
      m++;
  }

  // search remaining for regular shared objects
  for (auto it = mapping_list.begin(); it != mapping_list.end(); it++) {
    auto km = *it;
    string name = km.fsname();
    if (!name.empty()) {
      libraries[name].segments.push_back(km.start());
      if (km.prot() & PROT_EXEC) {
        libraries[name].has_exec = true;
      }
    }
  }

  // now create the output string from what we found
  stringstream sstr;
  sstr << "<library-list>";
  sstr << hex;

  for (auto lib : libraries) {
    if (lib.second.has_exec) {
      sstr << "<library name=\"" << lib.first << "\">";
      for (auto seg : lib.second.segments) {
        sstr << "<segment address=\"" << seg << "\"/>";
      }
      sstr << "</library>";
    }
  }

  sstr << "</library-list>";
  return sstr.str();
}

} // namespace rr
