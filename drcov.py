import re
import struct
from .extras import file_name

MIN_DRCOV_FILE_SIZE = 20
DRCOV_VERSION = 3

DRCOV_HEADER_RE = r"DRCOV VERSION: (?P<version>\d+)\n"
MODULE_HEADER_V2_RE = r"Module Table: version (?P<version>\d+), count (?P<mod_num>\d+)\n"
BB_HEADER_RE = r"BB Table: (?P<bbcount>\d+) bbs\n"


class DRCovVersionMisMatch(Exception):
    pass


def check_module_header(drcov_file):
    header = drcov_file.readline().decode('utf-8')
    pattern = re.match(DRCOV_HEADER_RE, header)
    version = int(pattern.group('version'))
    if version != DRCOV_VERSION:
        raise DRCovVersionMisMatch
    drcov_file.readline()  # DRCOV FLAVOR line


def get_module_header_info(drcov_file):
    header = drcov_file.readline().decode('utf-8')
    pattern = re.match(MODULE_HEADER_V2_RE, header)
    drcov_file.readline()  # column names line
    return (int(pattern.group("mod_num")), int(pattern.group("version")))


def parse_module_entry(drcov_file, version):
    entry = drcov_file.readline().decode('utf-8')[:-1]
    entry = re.split(r",\s+", entry)
    if version == 2:
        return {"start": int(entry[1], 16), "name": file_name(entry[-1])}
    return {"start": int(entry[2], 16), "name": file_name(entry[-1])}


def read_module_list(drcov_file):
    modules = []
    check_module_header(drcov_file)
    mod_num, mod_version = get_module_header_info(drcov_file)
    for _ in range(mod_num):
        modules.append(parse_module_entry(drcov_file, mod_version))
    return modules


def parse_bb_header(drcov_file):
    header = drcov_file.readline().decode('utf-8')
    pattern = re.match(BB_HEADER_RE, header)
    return int(pattern.group("bbcount"))


def read_bb_list(drcov_file, module_count):
    bblist = [{} for _ in range(module_count)]
    bb_count = parse_bb_header(drcov_file)
    struct_fmt = '<IHH'
    struct_size = struct.calcsize(struct_fmt)
    struct_unpack = struct.Struct(struct_fmt).unpack_from
    for _ in range(bb_count):
        bb_struct = drcov_file.read(struct_size)
        offset, size, mod_num = struct_unpack(bb_struct)
        if mod_num > module_count:
            continue
        bblist[mod_num][offset] = size
    return bblist


def dead_module_elimination(modules, bbs):
    delete = []
    for i in range(len(bbs)):
        if not bbs[i]:
            delete.insert(0, i)
    for i in delete:
        del bbs[i]
        del modules[i]


def load(path):
    drcov_file = open(path, "rb")
    modules = read_module_list(drcov_file)
    bbs = read_bb_list(drcov_file, len(modules))
    drcov_file.close()
    dead_module_elimination(modules, bbs)
    return [modules, bbs]
