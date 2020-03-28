#!/usr/bin/env python3
#-------------------------------------------------------------------------------
# elftools example: elf_relocations.py
#
# An example of obtaining a relocation section from an ELF file and examining
# the relocation entries it contains.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import print_function
from elftools.elf.relocation import RelocationSection
from elftools.elf.elffile import ELFFile
import sys
import cxxfilt
from subprocess import check_output

def get_pid(name):
    """get single pid
    """
    return int(check_output(["pidof", "-s", name]))

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

class ProcessMemoryMap(object):
    """process memory map info
    """
    def __init__(self, process_name):
        """parse process /proc/pid/maps file
            process_name: string like app
        """
        pid = get_pid(process_name)
        self.maps_info = []
        maps_file = "/proc/{}/maps".format(pid)
        with open(maps_file) as f:
            for line in f:
                line = line.rstrip('\n')
                info = line.split()
                self.maps_info.append(info)

    def get_image_load_base(self, image_path_name):
        """return image load base address
            image_path_name: string like /foo/bar/liba.so
        """
        # /foo/bar/liba.so -> liba.so
        image_name = image_path_name.split('/')[-1]

        for info in self.maps_info:
            if len(info) != 6:
                continue

            name_in_map = info[-1].split('/')[-1]
            if name_in_map != image_name:
                continue

            address_range = info[0].split('-')
            return int(address_range[0], 16)

    def get_vtable_offset(self, image_path_name, class_name):
        """return vtable offset in image
            image_path_name: string like /foo/bar/liba.so
            class_name: c++ class name, like CPlayer
        """
        with open(image_path_name, 'rb') as f:
            elffile = ELFFile(f)
            section = elffile.get_section_by_name('.rela.dyn')

            if not isinstance(section, RelocationSection):
                return

            # cxx demangle name, like "vtable for CPlayer"
            vtable_name = "vtable for {}".format(class_name)

            # The symbol table section pointed to in sh_link
            symtable = elffile.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if rel['r_info_sym'] == 0:
                    continue

                symbol = symtable.get_symbol(rel['r_info_sym'])
                if symbol['st_name'] == 0:
                    continue

                symbol_name = symbol.name
                try:
                    symbol_name = cxxfilt.demangle(symbol_name)
                except InvalidName:
                    continue

                if symbol_name == vtable_name:
                    return symbol['st_value']

if __name__ == '__main__':
    process_maps = ProcessMemoryMap("app")

    image_load_base = process_maps.get_image_load_base("player/libplayer.so")
    vtable_offset = process_maps.get_vtable_offset("player/libplayer.so", "CPlayer")
    vtable_runtime_addr = (image_load_base + vtable_offset + 16)

    print("vtable_runtime_addr of CPlayer is", hex(vtable_runtime_addr))