#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from subprocess import check_output, CalledProcessError, STDOUT
from elftools.elf.elffile import ELFFile
import struct
import sys
import cxxfilt
import argparse

SCRIPT_DESCRIPTION = "Dump cxx class instance count"

def dump_process_memory(pid, memfile, mem_begin, mem_end):
    """Dump process memory with gdb
    """
    gdb_dump_cmd = 'gdb --batch --pid {} -ex "dump memory {} {} {}"'.format(
        pid, memfile, mem_begin, mem_end)
    try:
        out_print = check_output(gdb_dump_cmd, stderr=STDOUT, shell=True)
        # out_print = out_print.decode(encoding='utf-8')
        # print(out_print, end='', file=sys.stdout)
    except CalledProcessError as ex:
        out_print = ex.output.decode(encoding='utf-8')
        print(out_print, end='', file=sys.stderr)
        sys.exit(ex.returncode)

def load_dump_memory(memfile):
    """Load and parse dump memory
        return [(ptr, cnt),]
    """
    all_unpacked = []
    with open(memfile, "rb") as f:
        all_bytes = f.read()
        try:
            off = 0
            while True:
                unpacked = struct.unpack_from("<QQ", all_bytes, offset=off)
                all_unpacked.append(unpacked)
                off += 16
        except struct.error:
            pass

    return all_unpacked

def get_object_load_base(pid, elf_file):
    """return executable or shared library object base address in a process
        pid: process id
        elf_file: object name loaded by process, like "/foo/bar.so" or "bar.so"
    """
    # /foo/bar.so -> bar.so
    obj_name = elf_file.rpartition('/')[2]

    maps_file = "/proc/{}/maps".format(pid)
    with open(maps_file) as f:
        for line in f:
            info = line.rstrip('\n').split()
            if len(info) != 6:
                continue

            base_name = info[-1].rpartition('/')[2]
            if base_name != obj_name:
                continue

            address_range = info[0].split('-')
            return int(address_range[0], 16)

class MyELF(object):
    """ELF file wrapper"""
    def __init__(self, elf_file):
        self.elffile = ELFFile(elf_file)

    def get_section_addr_size(self, section_name):
        """return section address and size
        """
        section = self.elffile.get_section_by_name(section_name)
        return section["sh_addr"], section["sh_size"]

    def get_classname_by_vptr(self, vptr):
        """Get class name by virtual table ptr
            return class name
        """
        classname = "Not found"
        sec_dynsym = self.elffile.get_section_by_name(".dynsym")
        if not sec_dynsym:
            return classname

        for nsym, symbol in enumerate(sec_dynsym.iter_symbols()):
            addr_value = symbol['st_value']
            if addr_value != vptr:
                continue

            try:
                classname = cxxfilt.demangle(symbol.name).rpartition(' ')[2]
            except cxxfilt.InvalidName:
                classname = symbol.name

            # Assert begin
            sec_rela_dyn = self.elffile.get_section_by_name(".rela.dyn")
            found_rela = False
            if sec_rela_dyn:
                for rela in sec_rela_dyn.iter_relocations():
                    if nsym == rela['r_info_sym']:
                        found_rela = True
                        break
            assert(found_rela)
            # Assert end

            break

        return classname


class Column2Table(object):
    """Print table like
        Class           Count
        ----------------------
        CPlayer         111111
        CLotteryPlayer  2222  
    """
    def __init__(self, col0name, col1name, table, keycol):
        maxlen_col0 = len(col0name)
        maxlen_col1 = len(col1name)
        for col0, col1 in table:
            maxlen_col0 = max(maxlen_col0, len(str(col0)))
            maxlen_col1 = max(maxlen_col1, len(str(col1)))
        table.sort(key = lambda x : x[keycol], reverse = True)
        self.table = table
        self.maxlen_col0 = maxlen_col0
        self.maxlen_col1 = maxlen_col1
        self.col0name = col0name
        self.col1name = col1name

    def _print_line(self, col0, col1):
        line = "{}{}{}{}".format(col0, (self.maxlen_col0-len(str(col0))+2)*' ',
                col1, (self.maxlen_col1-len(str(col1)))*' ')
        print(line)
    
    def _print_header(self):
        self._print_line(self.col0name, self.col1name)
        print((self.maxlen_col0+2+self.maxlen_col1)*'-')

    def print_table(self):
        self._print_header()
        for col0, col1 in self.table:
            self._print_line(col0, col1)

def main():
    argparser = argparse.ArgumentParser(
        usage="%(prog)s <-p pid> <-e elf> [-m memfile]",
        description=SCRIPT_DESCRIPTION,
        add_help=False,
        prog="dumpinstcnt.py")

    argparser.add_argument("-p", dest="pid", required=True)
    argparser.add_argument("-e", dest="elf", required=True)
    argparser.add_argument("-m", dest="memfile", default="/tmp/dumpinstcnt.mem",)

    # for debug
    # args = argparser.parse_args(["-p", "3950",
    #     "-e", "/home/kun/Develop/tcelf/player/libplayer.so"])

    args = argparser.parse_args()

    with open(args.elf, 'rb') as elf_file:
        myelf = MyELF(elf_file)
        sec_addr, sec_size = myelf.get_section_addr_size(".class.counter")
        load_base = get_object_load_base(args.pid, args.elf)

        mem_begin = hex(load_base + sec_addr)
        mem_end = hex(load_base + sec_addr + sec_size)
        dump_process_memory(args.pid, args.memfile, mem_begin, mem_end)
        all_unpacked = load_dump_memory(args.memfile)
        
        classname_count = []
        for cnt, vptr in all_unpacked:
            classname = myelf.get_classname_by_vptr(vptr-load_base-16)
            classname_count.append((classname, cnt))

        tbl = Column2Table("Class", "Count", classname_count, 1)
        tbl.print_table()

if __name__ == "__main__":
    main()
