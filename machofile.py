#!/usr/bin/python

"""machofile, Mach-O file reader module

The Mach-O file format is the executable file format used 
by macOS, iOS, watchOS, and tvOS.

Inspired by pefile, this module aims to provide a similar 
capability but for Mach-O binaries instead. The basic structures 
and constant are taken from the Mach-O header file (loader.h) 
from the xnu kernel source code. Reference material and documentation 
used to gain the file format knowledge are listed below.

Reference/Documentation links:
- https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
- https://github.com/apple-oss-distributions/lldb/blob/10de1840defe0dff10b42b9c56971dbc17c1f18c/llvm/include/llvm/Support/MachO.h
- https://iphonedev.wiki/Mach-O_File_Format
- https://lowlevelbits.org/parsing-mach-o-files/
- https://github.com/aidansteele/osx-abi-macho-file-format-reference
- https://lief-project.github.io/doc/latest/tutorials/11_macho_modification.html
- https://github.com/VirusTotal/yara/blob/master/libyara/include/yara/macho.h

Copyright (c) 2023-2025 Pasquale Stirparo <pstirparo@threatresearch.ch>
"""

# struct mach_header {
#     uint32_t      magic;
#     cpu_type_t    cputype;
#     cpu_subtype_t cpusubtype;
#     uint32_t      filetype;
#     uint32_t      ncmds;
#     uint32_t      sizeofcmds;
#     uint32_t      flags;
#     uint32_t      reserved;  // This is the additional field for 64-bit
# };

# struct load_command {
#     uint32_t cmd;
#     uint32_t cmdsize;
# };

# struct segment_command {
#     uint32_t    cmd;
#     uint32_t    cmdsize;
#     struct segment_command { // for 32-bit architectures
#         char        segname[16];
#         uint32_t    vmaddr;
#         uint32_t    vmsize;
#         uint32_t    fileoff;
#         uint32_t    filesize;
#         vm_prot_t   maxprot;
#         vm_prot_t   initprot;
#         uint32_t    nsects;
#         uint32_t    flags;
#     } segment_command;
# };

# struct dylib_command {
#     uint32_t cmd;
#     uint32_t cmdsize;
#     struct dylib {
#         union lc_str name;
#         uint32_t timestamp;
#         uint32_t current_version;
#         uint32_t compatibility_version;
#     } dylib;
# };

# struct symtab_command {
#     uint32_t cmd;        /* LC_SYMTAB */
#     uint32_t cmdsize;    /* sizeof(struct symtab_command) */
#     uint32_t symoff;     /* symbol table offset */
#     uint32_t nsyms;      /* number of symbol table entries */
#     uint32_t stroff;     /* string table offset */
#     uint32_t strsize;    /* string table size in bytes */
# };

# struct dysymtab_command {
#     uint32_t cmd;           /* LC_DYSYMTAB */
#     uint32_t cmdsize;         /* sizeof(struct dysymtab_command) */
#     uint32_t ilocalsym;	    /* index to local symbols */
#     uint32_t nlocalsym;	    /* number of local symbols */
#     uint32_t iextdefsym;      /* index to externally defined symbols */
#     uint32_t nextdefsym;      /* number of externally defined symbols */
#     uint32_t iundefsym;	    /* index to undefined symbols */
#     uint32_t nundefsym;	    /* number of undefined symbols */
#     uint32_t tocoff;	        /* file offset to table of contents */
#     uint32_t ntoc;            /* number of entries in table of contents */
#     uint32_t modtaboff;	    /* file offset to module table */
#     uint32_t nmodtab;	        /* number of module table entries */
#     uint32_t extrefsymoff;    /* offset to referenced symbol table */
#     uint32_t nextrefsyms;     /* number of referenced symbol table entries */
#     uint32_t indirectsymoff;  /* file offset to the indirect symbol table */
#     uint32_t nindirectsyms;   /* number of indirect symbol table entries */
#     uint32_t extreloff;	    /* offset to external relocation entries */
#     uint32_t nextrel;	        /* number of external relocation entries */
#     uint32_t locreloff;	    /* offset to local relocation entries */
#     uint32_t nlocrel;	        /* number of local relocation entries */
# };

__author__ = "Pasquale Stirparo"
__version__ = "2025.07.24 alpha"
__contact__ = "pstirparo@threatresearch.ch"

from hashlib import sha256
from hashlib import md5
from hashlib import sha1
import struct
import os
import io


def two_way_dict(pairs):
    return dict([(e[1], e[0]) for e in pairs] + pairs)


# Mach-O header formats
MACHO_HEADER_FORMAT_32 = "IiiIIII"
MACHO_HEADER_FORMAT_64 = "IiiIIIII"
LOAD_COMMAND_FORMAT = "II"
SEGMENT_COMMAND_FORMAT_32 = "16sIIIIIIII"
SEGMENT_COMMAND_FORMAT_64 = "16sQQQQIIII"
DYLIB_COMMAND_FORMAT = "IIII"
SYMTAB_COMMAND_FORMAT = "IIIIII"
DYSYMTAB_COMMAND_FORMAT = "IIIIIIIIIIIIIIIIII"

STRUCT_SIZEOF_TYPES = {
    "x": 1,
    "c": 1,
    "b": 1,
    "B": 1,
    "h": 2,
    "H": 2,
    "i": 4,
    "I": 4,
    "l": 4,
    "L": 4,
    "f": 4,
    "q": 8,
    "Q": 8,
    "d": 8,
    "s": 1,
}

# Mach-O constants and mappings
MH_MAGIC = 0xFEEDFACE  # Big endian, 32 bit Mach-O
MH_CIGAM = 0xCEFAEDFE  # Little endian, 32 bit Mach-O
MH_MAGIC_64 = 0xFEEDFACF  # Big endian, 64 bit Mach-O
MH_CIGAM_64 = 0xCFFAEDFE  # Little endian, 64 bit Mach-O

MAGIC_MAP = {
    MH_MAGIC: "MH_MAGIC (32-bit)",
    MH_CIGAM: "MH_CIGAM (32-bit reversed)",
    MH_MAGIC_64: "MH_MAGIC_64 (64-bit)",
    MH_CIGAM_64: "MH_CIGAM_64 (64-bit reversed)",
}

# Mach-O universal binary magic constants
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

FAT_MAGIC_MAP = {
    FAT_MAGIC: "FAT_MAGIC (32-bit)",
    FAT_CIGAM: "FAT_CIGAM (32-bit reversed)",
    FAT_MAGIC_64: "FAT_MAGIC_64 (64-bit)",
    FAT_CIGAM_64: "FAT_CIGAM_64 (64-bit reversed)",
}

# CPU masks, types and mappings
CPU_ARCH_MASK = 0xFF000000  # Mask for architecture bits
CPU_ARCH_ABI64 = 0x01000000  # 64-bit ABI mask (for cputype)
CPU_SUBTYPE_LIB64 = 0x80000000  # 64-bit library mask (for cpusubtype)

# Mach-O CPU Types
CPU_TYPE_X86 = 0x7
CPU_TYPE_X86_64 = 0x1000007
CPU_TYPE_ARM = 0xC
CPU_TYPE_ARM64 = 0x100000C
CPU_TYPE_PPC = 0x12
CPU_TYPE_PPC64 = 0x10000012
CPU_TYPE_SPARC = 0x14
CPU_TYPE_I860 = 0x15
CPU_TYPE_I386 = 0x7
CPU_TYPE_MC680X0 = 0x6
CPU_TYPE_MC98000 = 0xA
CPU_TYPE_HPPA = 0xB
CPU_TYPE_MC88000 = 0xD
CPU_TYPE_ALPHA = 0x10

CPU_TYPE_MAP = {
    CPU_TYPE_X86: "x86",
    CPU_TYPE_X86_64: "x86_64",
    CPU_TYPE_ARM: "ARM",
    CPU_TYPE_ARM64: "ARM 64-bit",
    CPU_TYPE_PPC: "PowerPC",
    CPU_TYPE_PPC64: "PowerPC 64-bit",
    CPU_TYPE_SPARC: "SPARC",
    CPU_TYPE_I860: "Intel i860",
    CPU_TYPE_I386: "Intel i386",
    CPU_TYPE_MC680X0: "Motorola 68000",
    CPU_TYPE_MC98000: "Motorola PowerPC",
    CPU_TYPE_HPPA: "HP PA-RISC",
    CPU_TYPE_MC88000: "Motorola 88000",
    CPU_TYPE_ALPHA: "DEC Alpha",
}

CPU_SUB_TYPE_MAP = {
    3: "x86_ALL",
    4: "x86_ARCH1",
    8: "x86_64_ALL",
    9: "x86_64_H",
    10: "x86_64_LIB64",
}

# list comprehensive but still incomplete. tbd.
cpu_subtypes = [
    ("CPU_SUBTYPE_386", 0x3),
    ("CPU_SUBTYPE_486", 0x4),
    ("CPU_SUBTYPE_486SX", 0x84),
    ("CPU_SUBTYPE_586", 0x5),
    ("CPU_SUBTYPE_PENT", 0x5),
    ("CPU_SUBTYPE_PENTPRO", 0x16),
    ("CPU_SUBTYPE_PENTII_M3", 0x36),
    ("CPU_SUBTYPE_PENTII_M5", 0x56),
    ("CPU_SUBTYPE_CELERON", 0x67),
    ("CPU_SUBTYPE_CELERON_MOBILE", 0x77),
    ("CPU_SUBTYPE_PENTIUM_3", 0x8),
    ("CPU_SUBTYPE_PENTIUM_3_M", 0x18),
    ("CPU_SUBTYPE_PENTIUM_3_XEON", 0x28),
    ("CPU_SUBTYPE_PENTIUM_M", 0x9),
    ("CPU_SUBTYPE_PENTIUM_4", 0xA),
    ("CPU_SUBTYPE_PENTIUM_4_M", 0x1A),
    ("CPU_SUBTYPE_ITANIUM", 0xB),
    ("CPU_SUBTYPE_ITANIUM_2", 0x1B),
    ("CPU_SUBTYPE_XEON", 0xC),
    ("CPU_SUBTYPE_XEON_MP", 0x1C),
    ("CPU_SUBTYPE_ARM_ALL", 0x0),
    ("CPU_SUBTYPE_ARM_V4T", 0x5),
    ("CPU_SUBTYPE_ARM_V6", 0x6),
    ("CPU_SUBTYPE_ARM_V5", 0x7),
    ("CPU_SUBTYPE_ARM_V5TEJ", 0x7),
    ("CPU_SUBTYPE_ARM_XSCALE", 0x8),
    ("CPU_SUBTYPE_ARM_V7", 0x9),
    ("CPU_SUBTYPE_ARM_V7F", 0xA),
    ("CPU_SUBTYPE_ARM_V7S", 0xB),
    ("CPU_SUBTYPE_ARM_V7K", 0xC),
    ("CPU_SUBTYPE_ARM_V6M", 0xE),
    ("CPU_SUBTYPE_ARM_V7M", 0xF),
    ("CPU_SUBTYPE_ARM_V7EM", 0x10),
    ("CPU_SUBTYPE_ARM_V8", 0xD),
    ("CPU_SUBTYPE_ARM64_ALL", 0x0),
    ("CPU_SUBTYPE_ARM64_V8", 0x1),
]

CPU_SUBTYPE_MAP = two_way_dict(cpu_subtypes)

# Mach-O header filetypes
macho_header_filetype = [
    ("MH_OBJECT", 0x1),
    ("MH_EXECUTE", 0x2),
    ("MH_FVMLIB", 0x3),
    ("MH_CORE", 0x4),
    ("MH_PRELOAD", 0x5),
    ("MH_DYLIB", 0x6),
    ("MH_DYLINKER", 0x7),
    ("MH_BUNDLE", 0x8),
    ("MH_DYLIB_STUB", 0x9),
    ("MH_DSYM", 0xA),
    ("MH_KEXT_BUNDLE", 0xB),
]

MACHO_FILETYPE = two_way_dict(macho_header_filetype)

FLAGS_MAP = {
    0x1: "MH_NOUNDEFS",
    0x2: "MH_INCRLINK",
    0x4: "MH_DYLDLINK",
    0x8: "MH_BINDATLOAD",
    0x10: "MH_PREBOUND",
    0x20: "MH_SPLIT_SEGS",
    0x40: "MH_LAZY_INIT",
    0x80: "MH_TWOLEVEL",
    0x100: "MH_FORCE_FLAT",
    0x200: "MH_NOMULTIDEFS",
    0x400: "MH_NOFIXPREBINDING",
    0x800: "MH_PREBINDABLE",
    0x1000: "MH_ALLMODSBOUND",
    0x2000: "MH_SUBSECTIONS_VIA_SYMBOLS",
    0x4000: "MH_CANONICAL",
    0x8000: "MH_WEAK_DEFINES",
    0x10000: "MH_BINDS_TO_WEAK",
    0x20000: "MH_ALLOW_STACK_EXECUTION",
    0x40000: "MH_ROOT_SAFE",
    0x80000: "MH_SETUID_SAFE",
    0x100000: "MH_NO_REEXPORTED_DYLIBS",
    0x200000: "MH_PIE",
    0x400000: "MH_DEAD_STRIPPABLE_DYLIB",
    0x800000: "MH_HAS_TLV_DESCRIPTORS",
    0x1000000: "MH_NO_HEAP_EXECUTION",
    0x2000000: "MH_APP_EXTENSION_SAFE",
    0x4000000: "MH_NLIST_OUTOFSYNC_WITH_DYLDINFO",
    0x8000000: "MH_SIM_SUPPORT",
    0x80000000: "MH_DYLIB_IN_CACHE",
}

# Symbol table constants for the "n_type" field in nlist and nlist_64 structures
# Constant masks for the "n_type" field
N_STAB = 0xE0  # Mask for STAB (debug) symbols
N_PEXT = 0x10  # Mask for private external symbols
N_TYPE = 0x0E  # Mask for symbol type bits
N_EXT  = 0x01  # Mask for external symbols

# Constants for the "n_type & N_TYPE" values
N_UNDF = 0x0   # Undefined symbol
N_ABS  = 0x2   # Absolute symbol
N_SECT = 0xE   # Section symbol
N_PBUD = 0xC   # Prebound undefined symbol
N_INDR = 0xA   # Indirect symbol

# Constants for the "cmd" field in the load command structure
load_command_types = [
    ("LC_SEGMENT", 0x1),
    ("LC_SYMTAB", 0x2),
    ("LC_SYMSEG", 0x3),
    ("LC_THREAD", 0x4),
    ("LC_UNIXTHREAD", 0x5),
    ("LC_LOADFVMLIB", 0x6),
    ("LC_IDFVMLIB", 0x7),
    ("LC_IDENT", 0x8),
    ("LC_FVMFILE", 0x9),
    ("LC_PREPAGE", 0xA),
    ("LC_DYSYMTAB", 0xB),
    ("LC_LOAD_DYLIB", 0xC),
    ("LC_ID_DYLIB", 0xD),
    ("LC_LOAD_DYLINKER", 0xE),
    ("LC_ID_DYLINKER", 0xF),
    ("LC_PREBOUND_DYLIB", 0x10),
    ("LC_ROUTINES", 0x11),
    ("LC_SUB_FRAMEWORK", 0x12),
    ("LC_SUB_UMBRELLA", 0x13),
    ("LC_SUB_CLIENT", 0x14),
    ("LC_SUB_LIBRARY", 0x15),
    ("LC_TWOLEVEL_HINTS", 0x16),
    ("LC_PREBIND_CKSUM", 0x17),
    ("LC_LOAD_WEAK_DYLIB", 0x18 | 0x80000000),
    ("LC_SEGMENT_64", 0x19),
    ("LC_ROUTINES_64", 0x1A),
    ("LC_UUID", 0x1B),
    ("LC_RPATH", 0x1C | 0x80000000),
    ("LC_CODE_SIGNATURE", 0x1D),
    ("LC_SEGMENT_SPLIT_INFO", 0x1E),
    ("LC_REEXPORT_DYLIB", 0x1F | 0x80000000),
    ("LC_LAZY_LOAD_DYLIB", 0x20),
    ("LC_ENCRYPTION_INFO", 0x21),
    ("LC_DYLD_INFO", 0x22),
    ("LC_DYLD_INFO_ONLY", 0x22 | 0x80000000),
    ("LC_LOAD_UPWARD_DYLIB", 0x23 | 0x80000000),
    ("LC_VERSION_MIN_MACOSX", 0x24),
    ("LC_VERSION_MIN_IPHONEOS", 0x25),
    ("LC_FUNCTION_STARTS", 0x26),
    ("LC_DYLD_ENVIRONMENT", 0x27),
    ("LC_MAIN", 0x28 | 0x80000000),
    ("LC_DATA_IN_CODE", 0x29),
    ("LC_SOURCE_VERSION", 0x2A),
    ("LC_DYLIB_CODE_SIGN_DRS", 0x2B),
    ("LC_ENCRYPTION_INFO_64", 0x2C),
    ("LC_LINKER_OPTIONS", 0x2D),
    ("LC_LINKER_OPTIMIZATION_HINT", 0x2E),
    ("LC_VERSION_MIN_TVOS", 0x2F),
    ("LC_VERSION_MIN_WATCHOS", 0x30),
]

LOAD_COMMAND_TYPES = two_way_dict(load_command_types)

dylib_command_types = [
    ("LC_ID_DYLIB", 0xD),
    ("LC_LOAD_DYLIB", 0xC),
    ("LC_LOAD_WEAK_DYLIB", 0x18),
]

DYLIB_CMD_TYPES = two_way_dict(dylib_command_types)


class MachO:
    """A Mach-O representation.

    This class represents a Mach-O file, providing methods to parse it and
    access most of its structures and data.

    It expect to be supplied with either a file path or a data buffer to parse.

    macho = MachO(file_path='/path/to/machobinary')
    macho = MachO('/path/to/machobinary')

    The above two lines are equivalent and would load the Mach-O file and parse it.
    If the data buffer is already available, it can be supplied directly with:

    macho = MachO(data=bytes_variable)

    Attributes:
        general_info: A dictionary containing general information about the Mach-O file.
        header: A dictionary containing the Mach-O header.
        load_commands: A list of dictionaries containing the Mach-O load commands.
        load_commands_set: A set of the Mach-O load commands.
        segments: A list of dictionaries containing the Mach-O segments.
        dylib_commands: A list of dictionaries containing the Mach-O dylib commands.
        dylib_names: A list of the Mach-O dylib names.
    """

    def __init__(self, file_path=None, data=None):
        if file_path is None and data is None:
            raise ValueError("Must supply either name or data")
        elif file_path is not None:
            self.file_path = file_path
            self.fh = open(file_path, "rb")
            self.data = self.fh.read()
            self.fh.close()
        else:
            self.data = data

        self.f = io.BytesIO(self.data)

        self.general_info = {}
        self.header = {}
        self.load_commands = []
        self.load_commands_set = set()
        self.segments = []
        self.dylib_commands = []
        self.dylib_names = []
        self.imported_functions = {}
        self.exported_symbols = {}

    def parse(self):
        """Parse a Mach-O file.

        Loads a Mach-O file, parsing all its structures and making them available
        through the instance's attributes.
        """
        self.general_info = self.get_general_info()
        self.header = self.get_macho_header()
        self.load_commands, self.load_commands_set = self.get_macho_load_cmd_table()
        self.segments = self.get_file_segments()
        self.dylib_commands, self.dylib_names = self.get_dylib_commands()
        self.imported_functions = self.get_imported_functions()
        self.exported_symbols = self.get_exported_symbols()

    def decode_cpusubtype(self, cputype, cpusubtype_value):
        mask = 0xFFFFFFFF  # to get unsigned value
        cpusubtype_value = cpusubtype_value & mask
        decoded_subtypes = []

        # Check if the cpusubtype is combined or singular
        for subtype, subtype_name in CPU_SUB_TYPE_MAP.items():
            if cpusubtype_value & subtype:
                decoded_subtypes.append(subtype_name)
        return (
            ", ".join(decoded_subtypes) if decoded_subtypes else str(cpusubtype_value)
        )

    def decode_flags(self, flags_value):
        decoded_flags = []
        for flag, flag_name in FLAGS_MAP.items():
            if flags_value & flag:
                # Remove 'MH_' prefix if present
                if flag_name.startswith('MH_'):
                    decoded_flags.append(flag_name[3:])
                else:
                    decoded_flags.append(flag_name)
        return ", ".join(decoded_flags) if decoded_flags else str(flags_value)

    def get_general_info(self):
        """Get general information about a Mach-O file.

        Returns:
            info_dict: A dictionary containing general information about the Mach-O file,
                more specifically: filename (str), filesize (int), filetype (str),
                file_flags (str), md5 (str), sha1 (str), sha256(str).
        """
        if self.file_path is None:
            filename = "-"
        else:
            filename = os.path.basename(self.file_path)
        md5_hash = md5()
        sha256_hash = sha256()
        sha1_hash = sha1()
        md5_hash.update(self.data)
        sha1_hash.update(self.data)
        sha256_hash.update(self.data)
        # Parse Mach-O header to get filetype and flags
        self.f.seek(0)
        magic = struct.unpack("I", self.f.read(4))[0]
        byte_order = ">" if magic in {MH_CIGAM, MH_CIGAM_64} else "<"
        self.f.seek(0)
        if magic in {MH_MAGIC, MH_CIGAM}:
            header_size = struct.calcsize(byte_order + MACHO_HEADER_FORMAT_32)
            header_data = self.f.read(header_size)
            header = struct.unpack(byte_order + MACHO_HEADER_FORMAT_32, header_data)
        else:
            header_size = struct.calcsize(byte_order + MACHO_HEADER_FORMAT_64)
            header_data = self.f.read(header_size)
            header = struct.unpack(byte_order + MACHO_HEADER_FORMAT_64, header_data)
        filetype = MACHO_FILETYPE[header[3]]
        if filetype.startswith('MH_'):
            filetype = filetype[3:]
        file_flags = self.decode_flags(header[6])
        info_dict = {
            "Filename": filename,
            "Filesize": len(self.data),
            "Filetype": filetype,
            "Flags": file_flags,
            "MD5": md5_hash.hexdigest(),
            "SHA1": sha1_hash.hexdigest(),
            "SHA256": sha256_hash.hexdigest(),
        }
        return info_dict

    def get_macho_header(self):
        """Get the Mach-O header.

        Returns:
            header_dict: A dictionary containing the Mach-O header, more specifically:
                magic (str), cputype (str), cpusubtype (str), filetype (str), ncmds (int),
                sizeofcmds (int), flags (str).
        """

        self.f.seek(0)
        # Read the magic value to determine byte order
        magic = struct.unpack("I", self.f.read(4))[0]
        byte_order = ">" if magic in {MH_CIGAM, MH_CIGAM_64} else "<"  # endianness

        # Position back to start of file for full header read
        self.f.seek(0)
        if magic in {MH_MAGIC, MH_CIGAM}:
            header_size = struct.calcsize(byte_order + MACHO_HEADER_FORMAT_32)
            header_data = self.f.read(header_size)
            header = struct.unpack(byte_order + MACHO_HEADER_FORMAT_32, header_data)
        else:
            header_size = struct.calcsize(byte_order + MACHO_HEADER_FORMAT_64)
            header_data = self.f.read(header_size)
            header = struct.unpack(byte_order + MACHO_HEADER_FORMAT_64, header_data)

        filetype = MACHO_FILETYPE[header[3]]
        if filetype.startswith('MH_'):
            filetype = filetype[3:]
        magic_val = header[0]
        magic_str = MAGIC_MAP.get(magic_val, magic_val)
        magic_field = f"{magic_str}, 0x{magic_val:08X}" if isinstance(magic_str, str) else f"0x{magic_val:08X}"
        header_dict = {
            "magic": magic_field,
            "cputype": CPU_TYPE_MAP.get(header[1], header[1]),
            "cpusubtype": self.decode_cpusubtype(header[1], header[2]),
            "filetype": filetype,
            "ncmds": header[4],
            "sizeofcmds": header[5],
            "flags": self.decode_flags(header[6]),
        }

        return header_dict

    def get_macho_load_cmd_table(self):
        """Get the Mach-O load command table.

        Returns:
            load_commands: A list of dictionaries containing the Mach-O load commands.
                Each dictionary contains the following keys: cmd (str), cmdsize (int).
            load_commands_set: A set of the Mach-O load commands, each itemn as (str).
        """
        load_commands = []
        self.f.seek(0)
        # Read the magic value to determine byte order and architecture
        magic = struct.unpack("I", self.f.read(4))[0]
        byte_order = ">" if magic in {MH_CIGAM, MH_CIGAM_64} else "<"  # endianness

        # Depending on architecture, read the correct Mach-O header
        self.f.seek(0)
        if magic in {MH_MAGIC, MH_CIGAM}:
            header_size = struct.calcsize(byte_order + MACHO_HEADER_FORMAT_32)
        else:
            header_size = struct.calcsize(byte_order + MACHO_HEADER_FORMAT_64)

        header_data = self.f.read(header_size)
        if magic in {MH_MAGIC, MH_CIGAM}:
            _, _, _, filetype, ncmds, sizeofcmds, _ = struct.unpack(
                byte_order + MACHO_HEADER_FORMAT_32, header_data
            )
        else:
            _, _, _, filetype, ncmds, sizeofcmds, _, _ = struct.unpack(
                byte_order + MACHO_HEADER_FORMAT_64, header_data
            )

        # Parse each load command
        for _ in range(ncmds):
            cmd_data = self.f.read(struct.calcsize(byte_order + LOAD_COMMAND_FORMAT))
            cmd, cmdsize = struct.unpack(byte_order + LOAD_COMMAND_FORMAT, cmd_data)
            load_commands.append({"cmd": LOAD_COMMAND_TYPES[cmd], "cmdsize": cmdsize})
            # Move the file pointer past this load command to the start of the next one
            self.f.seek(
                self.f.tell()
                + cmdsize
                - struct.calcsize(byte_order + LOAD_COMMAND_FORMAT)
            )

        loadcommans_set = set(load_command["cmd"] for load_command in load_commands)
        if "LC_SEGMENT_64" in loadcommans_set:
            loadcommans_set.remove("LC_SEGMENT_64")
        if "LC_SEGMENT" in loadcommans_set:
            loadcommans_set.remove("LC_SEGMENT")

        return load_commands, loadcommans_set

    def get_file_segments(self):
        """Get the Mach-O segments.

        Returns:
            segments: A list of dictionaries, each containing the Mach-O segments.
                More specifically: segname (str), vaddr (int), vsize (int), offset (int),
                size (int), max_vm_protection (int), initial_vm_protection (int),
                nsects (int), flags (int).
        """
        self.f.seek(0)
        segments = []

        magic = struct.unpack("I", self.f.read(4))[0]
        is_64_bit = True if magic in {MH_MAGIC_64, MH_CIGAM_64} else False
        byte_order = ">" if magic in {MH_CIGAM, MH_CIGAM_64} else "<"  # endianness

        # Adjust the position to skip cputype and cpusubtype
        self.f.seek(12, 1)

        # Get number of load commands from header
        ncmds = struct.unpack("I", self.f.read(4))[0]

        # Skip over the rest of the Mach-O header to reach load commands
        if is_64_bit:
            self.f.seek(12, 1)  # Skip the remainder of the 64-bit Mach-O header
        else:
            self.f.seek(8, 1)  # Skip the remainder of the 32-bit Mach-O header

        # Process each load command
        for _ in range(ncmds):
            # Read command type and size
            cmd, cmdsize = struct.unpack(
                byte_order + LOAD_COMMAND_FORMAT, self.f.read(8)
            )

            # If it's an LC_SEGMENT, process it
            if (
                cmd == LOAD_COMMAND_TYPES["LC_SEGMENT"]
                or cmd == LOAD_COMMAND_TYPES["LC_SEGMENT_64"]
            ):
                if is_64_bit:
                    segment_size = struct.calcsize(
                        byte_order + SEGMENT_COMMAND_FORMAT_64
                    )
                    seg_data = self.f.read(segment_size)
                    (
                        segname,
                        vaddr,
                        vsize,
                        offset,
                        size,
                        max_vm_protection,
                        initial_vm_protection,
                        nsectors,
                        flags,
                    ) = struct.unpack(SEGMENT_COMMAND_FORMAT_64, seg_data)
                else:
                    segment_size = struct.calcsize(
                        byte_order + SEGMENT_COMMAND_FORMAT_32
                    )
                    seg_data = self.f.read(segment_size)
                    (
                        segname,
                        vaddr,
                        vsize,
                        offset,
                        size,
                        max_vm_protection,
                        initial_vm_protection,
                        nsectors,
                        flags,
                    ) = struct.unpack(SEGMENT_COMMAND_FORMAT_32, seg_data)
                segname = segname.decode("utf-8").rstrip("\0")
                tmp_dict = {
                    "segname": segname,
                    "vaddr": vaddr,
                    "vsize": vsize,
                    "offset": offset,
                    "size": size,
                    "max_vm_protection": max_vm_protection,
                    "initial_vm_protection": initial_vm_protection,
                    "nsects": nsectors,
                    "flags": flags,
                }
                segments.append((tmp_dict))
                # Move to the next command
                self.f.seek(cmdsize - segment_size - 8, 1)
            else:
                # Move to the next command
                self.f.seek(cmdsize - 8, 1)
        return segments

    def get_dylib_commands(self):
        """Get the Mach-O dylib commands.

        Returns:
            dylib_full_info: A list of dictionaries, each containing the Mach-O dylib commands.
                Each dictionary contains the following key/value pairs: dylib_name_offset (int),
                dylib_timestamp (int),
                dylib_current_version (int), dylib_compat_version (int), dylib_name (str).
            dylib_names: A list of the Mach-O dylib names. Each entry is represented in
                its raw form as binary string (bytes).
        """
        self.f.seek(0)
        dylib_full_info = []
        dylib_names = []

        magic = struct.unpack("I", self.f.read(4))[0]
        is_64_bit = True if magic in {MH_MAGIC_64, MH_CIGAM_64} else False
        byte_order = ">" if magic in {MH_CIGAM, MH_CIGAM_64} else "<"  # endianness

        # Adjust the position to skip cputype and cpusubtype
        self.f.seek(12, 1)

        # Get number of load commands from header
        ncmds = struct.unpack("I", self.f.read(4))[0]

        # Skip over the rest of the Mach-O header to reach load commands
        if is_64_bit:
            self.f.seek(12, 1)  # Skip the remainder of the 64-bit Mach-O header
        else:
            self.f.seek(8, 1)  # Skip the remainder of the 32-bit Mach-O header

        # Process each load command
        for _ in range(ncmds):
            # Read command type and size
            cmd, cmdsize = struct.unpack(
                byte_order + LOAD_COMMAND_FORMAT, self.f.read(8)
            )

            # If it's an LC_SEGMENT, process it
            if cmd in DYLIB_CMD_TYPES:
                dylib_size = struct.calcsize(byte_order + DYLIB_COMMAND_FORMAT)
                dylib_data = self.f.read(dylib_size)
                (
                    dylib_name_offset,
                    dylib_timestamp,
                    dylib_current_version,
                    dylib_compat_version,
                ) = struct.unpack(DYLIB_COMMAND_FORMAT, dylib_data)

                dylib_name_size = cmdsize - dylib_name_offset
                dylib_name = self.f.read(dylib_name_size).rstrip(b"\x00")
                tmp_dict = {
                    "dylib_name_offset": dylib_name_offset,
                    "dylib_timestamp": dylib_timestamp,
                    "dylib_current_version": dylib_current_version,
                    "dylib_compat_version": dylib_compat_version,
                    "dylib_name": dylib_name,
                }
                dylib_full_info.append((tmp_dict))
                dylib_names.append(dylib_name)
            else:
                # Move to the next command
                self.f.seek(cmdsize - 8, 1)
        return dylib_full_info, dylib_names

    def get_imported_functions(self):
        """Extract imported functions from the Mach-O file.

        Returns:
            imported_functions: dict mapping dylib name to list of imported symbols.
        """
        imported_functions_by_dylib = {}
        # Build a list of dylib names in the order they appear
        dylib_ordinals = []
        for d in self.dylib_names:
            # decode if bytes
            if isinstance(d, bytes):
                dylib_ordinals.append(d.decode(errors="replace"))
            else:
                dylib_ordinals.append(str(d))
        # Add a fallback for symbols with ordinal 0
        imported_functions_by_dylib["<unknown>"] = []

        self.f.seek(0)
        magic = struct.unpack("I", self.f.read(4))[0]
        is_64_bit = True if magic in {MH_MAGIC_64, MH_CIGAM_64} else False
        byte_order = ">" if magic in {MH_CIGAM, MH_CIGAM_64} else "<"  # endianness

        # Adjust the position to skip cputype and cpusubtype
        self.f.seek(12, 1)
        ncmds = struct.unpack("I", self.f.read(4))[0]
        if is_64_bit:
            self.f.seek(12, 1)
        else:
            self.f.seek(8, 1)

        symtab = None
        dysymtab = None
        # Find LC_SYMTAB and LC_DYSYMTAB
        for _ in range(ncmds):
            cmd_start = self.f.tell()
            cmd, cmdsize = struct.unpack(byte_order + LOAD_COMMAND_FORMAT, self.f.read(8))
            rest_of_cmd = self.f.read(cmdsize - 8)
            full_cmd = struct.pack(byte_order + LOAD_COMMAND_FORMAT, cmd, cmdsize) + rest_of_cmd
            if cmd == LOAD_COMMAND_TYPES["LC_SYMTAB"]:
                symtab = struct.unpack(byte_order + SYMTAB_COMMAND_FORMAT, full_cmd[:struct.calcsize(byte_order + SYMTAB_COMMAND_FORMAT)])
            elif cmd == LOAD_COMMAND_TYPES["LC_DYSYMTAB"]:
                dysymtab = struct.unpack(byte_order + DYSYMTAB_COMMAND_FORMAT, full_cmd[:struct.calcsize(byte_order + DYSYMTAB_COMMAND_FORMAT)])
            self.f.seek(cmd_start + cmdsize)

        if not symtab or not dysymtab:
            return imported_functions_by_dylib  # Could not find symbol tables

        # Unpack symtab
        symoff = symtab[2]
        nsyms = symtab[3]
        stroff = symtab[4]
        strsize = symtab[5]

        # Unpack dysymtab
        iundefsym = dysymtab[6]
        nundefsym = dysymtab[7]

        # Read string table
        self.f.seek(stroff)
        string_table = self.f.read(strsize)

        # Read symbol table
        self.f.seek(symoff)
        if is_64_bit:
            nlist_fmt = byte_order + "IbbHQ"  # n_strx, n_type, n_sect, n_desc, n_value
            nlist_size = struct.calcsize(nlist_fmt)
        else:
            nlist_fmt = byte_order + "IbbHI"  # n_strx, n_type, n_sect, n_desc, n_value
            nlist_size = struct.calcsize(nlist_fmt)

        # Only process undefined symbols (imported functions)
        for idx in range(iundefsym, iundefsym + nundefsym):
            self.f.seek(symoff + idx * nlist_size)
            entry = self.f.read(nlist_size)
            if len(entry) != nlist_size:
                continue
            if is_64_bit:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack(nlist_fmt, entry)
            else:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack(nlist_fmt, entry)
            if n_strx == 0:
                continue
            str_offset = n_strx
            if str_offset < len(string_table):
                name = string_table[str_offset:string_table.find(b"\x00", str_offset)]
                if not name:
                    continue
                symbol_name = name.decode(errors="replace")
                # Extract library ordinal from n_desc (high 8 bits)
                lib_ordinal = (n_desc >> 8) & 0xFF
                if lib_ordinal == 0 or lib_ordinal > len(dylib_ordinals):
                    imported_functions_by_dylib["<unknown>"].append(symbol_name)
                else:
                    dylib_name = dylib_ordinals[lib_ordinal - 1]
                    if dylib_name not in imported_functions_by_dylib:
                        imported_functions_by_dylib[dylib_name] = []
                    imported_functions_by_dylib[dylib_name].append(symbol_name)
        # Remove <unknown> if empty
        if not imported_functions_by_dylib["<unknown>"]:
            del imported_functions_by_dylib["<unknown>"]
        return imported_functions_by_dylib
    
    def get_exported_symbols(self):
        """Extract exported (defined external) symbols from the Mach-O file.

        Returns:
            exported_symbols: dict mapping dylib ordinal or '<unknown>' to list of exported symbols.
        """
        exported_symbols_by_dylib = {}
        # Build a list of dylib names in the order they appear (1-based ordinal)
        dylib_ordinals = []
        for d in self.dylib_names:
            if isinstance(d, bytes):
                dylib_ordinals.append(d.decode(errors="replace"))
            else:
                dylib_ordinals.append(str(d))
        exported_symbols_by_dylib["<unknown>"] = []

        self.f.seek(0)
        magic = struct.unpack("I", self.f.read(4))[0]
        is_64_bit = True if magic in {MH_MAGIC_64, MH_CIGAM_64} else False
        byte_order = ">" if magic in {MH_CIGAM, MH_CIGAM_64} else "<"  # endianness

        # Adjust the position to skip cputype and cpusubtype
        self.f.seek(12, 1)
        ncmds = struct.unpack("I", self.f.read(4))[0]
        if is_64_bit:
            self.f.seek(12, 1)
        else:
            self.f.seek(8, 1)

        symtab = None
        for _ in range(ncmds):
            cmd_start = self.f.tell()
            cmd, cmdsize = struct.unpack(byte_order + LOAD_COMMAND_FORMAT, self.f.read(8))
            rest_of_cmd = self.f.read(cmdsize - 8)
            full_cmd = struct.pack(byte_order + LOAD_COMMAND_FORMAT, cmd, cmdsize) + rest_of_cmd
            if cmd == LOAD_COMMAND_TYPES["LC_SYMTAB"]:
                symtab = struct.unpack(byte_order + SYMTAB_COMMAND_FORMAT, full_cmd[:struct.calcsize(byte_order + SYMTAB_COMMAND_FORMAT)])
            self.f.seek(cmd_start + cmdsize)

        if not symtab:
            return exported_symbols_by_dylib  # Could not find symbol table

        symoff = symtab[2]
        nsyms = symtab[3]
        stroff = symtab[4]
        strsize = symtab[5]

        self.f.seek(stroff)
        string_table = self.f.read(strsize)
        self.f.seek(symoff)
        if is_64_bit:
            nlist_fmt = byte_order + "IbbHQ"  # n_strx, n_type, n_sect, n_desc, n_value
            nlist_size = struct.calcsize(nlist_fmt)
        else:
            nlist_fmt = byte_order + "IbbHI"  # n_strx, n_type, n_sect, n_desc, n_value
            nlist_size = struct.calcsize(nlist_fmt)

        # Process all symbols in the symbol table
        for idx in range(nsyms):
            self.f.seek(symoff + idx * nlist_size)
            entry = self.f.read(nlist_size)
            if len(entry) != nlist_size:
                continue
            if is_64_bit:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack(nlist_fmt, entry)
            else:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack(nlist_fmt, entry)
            if n_strx == 0:
                continue

            str_offset = n_strx
            if str_offset < len(string_table):
                name = string_table[str_offset:string_table.find(b"\x00", str_offset)]
                if not name:
                    continue
                symbol_name = name.decode(errors="replace")
                # Only process defined external symbols (N_SECT and N_EXT)
                if (n_type & N_TYPE) == N_SECT and (n_type & N_EXT):
                    # Check if this is __mh_execute_header and calculate its file offset
                    if symbol_name == "__mh_execute_header":
                        # Calculate file offset from virtual address using segment mapping
                        file_offset = None
                        for segment in self.segments:
                            if (n_value >= segment["vaddr"] and 
                                n_value < segment["vaddr"] + segment["vsize"]):
                                # Calculate offset within the segment
                                offset_in_segment = n_value - segment["vaddr"]
                                file_offset = segment["offset"] + offset_in_segment
                                break
                        
                        # Exclude if file offset is 0 (default export)
                        if file_offset == 0:
                            continue
                    # Extract library ordinal from n_desc (high 8 bits)
                    lib_ordinal = (n_desc >> 8) & 0xFF
                    if lib_ordinal == 0 or lib_ordinal > len(dylib_ordinals):
                        exported_symbols_by_dylib["<unknown>"].append(symbol_name)
                    else:
                        dylib_name = dylib_ordinals[lib_ordinal - 1]
                        if dylib_name not in exported_symbols_by_dylib:
                            exported_symbols_by_dylib[dylib_name] = []
                        exported_symbols_by_dylib[dylib_name].append(symbol_name)
        # Remove <unknown> if empty
        if not exported_symbols_by_dylib["<unknown>"]:
            del exported_symbols_by_dylib["<unknown>"]
        return exported_symbols_by_dylib

    def get_import_hash(self):
        """Get the import hash of the Mach-O file.

        Returns:
            import_hash: the import hash of the Mach-O file.
        """
        sorted_lowered_imports = []
        
        for dylib, imports in self.imported_functions.items():
            for imp in imports:
                sorted_lowered_imports.append(imp.strip().lower())
        sorted_lowered_imports = sorted(sorted_lowered_imports)
        sorted_lowered_imports = list(dict.fromkeys(sorted_lowered_imports))
        import_hash = md5(",".join(sorted_lowered_imports).encode()).hexdigest()

        return import_hash

    def get_dylib_hash(self):
        """Get the dylib hash of the Mach-O file.

        Returns:
            dylib_hash: the dylib hash of the Mach-O file.
        """
        sorted_lowered_dylibs = []

        for dylib in self.dylib_names:
            sorted_lowered_dylibs.append(dylib.decode().lower())
        sorted_lowered_dylibs = sorted(sorted_lowered_dylibs)
        dylib_hash = md5(",".join(sorted_lowered_dylibs).encode()).hexdigest()

        return dylib_hash

    def get_export_hash(self):
        """Get the export hash of the Mach-O file.

        Returns:
            export_hash: the export hash of the Mach-O file.
        """
        sorted_lowered_exports = []
        if not self.exported_symbols:
            return None
        for dylib, exports in self.exported_symbols.items():
            for exp in exports:
                sorted_lowered_exports.append(exp.lower())
        sorted_lowered_exports = sorted(sorted_lowered_exports)
        sorted_lowered_exports = list(dict.fromkeys(sorted_lowered_exports))
        export_hash = md5(",".join(sorted_lowered_exports).encode()).hexdigest()

        return export_hash

    def get_symhash_dict(self):
        """Get the symhash for the Mach-O file, following the original Anomali Labs/CRITS logic.

        This method walks the symbol table, and for each symbol:
            - skips STAB (debug) symbols
            - includes only external symbols (n_type & N_EXT)
            - includes only undefined symbols (n_type & N_TYPE == N_UNDF)
        The resulting list of symbol names is sorted, joined with commas, and MD5 hashed.
        Returns:
            symhash_dict: dict mapping entity description ("cputype filetype magic") to symhash
        """
        symhash_dict = {}
        sym_list = []

        self.f.seek(0)
        magic = struct.unpack("I", self.f.read(4))[0]
        is_64_bit = True if magic in {MH_MAGIC_64, MH_CIGAM_64} else False
        byte_order = ">" if magic in {MH_CIGAM, MH_CIGAM_64} else "<"

        # Adjust the position to skip cputype and cpusubtype
        self.f.seek(12, 1)
        ncmds = struct.unpack("I", self.f.read(4))[0]
        if is_64_bit:
            self.f.seek(12, 1)
        else:
            self.f.seek(8, 1)

        symtab = None
        for _ in range(ncmds):
            cmd_start = self.f.tell()
            cmd, cmdsize = struct.unpack(byte_order + LOAD_COMMAND_FORMAT, self.f.read(8))
            rest_of_cmd = self.f.read(cmdsize - 8)
            full_cmd = struct.pack(byte_order + LOAD_COMMAND_FORMAT, cmd, cmdsize) + rest_of_cmd
            if cmd == LOAD_COMMAND_TYPES["LC_SYMTAB"]:
                symtab = struct.unpack(byte_order + SYMTAB_COMMAND_FORMAT, full_cmd[:struct.calcsize(byte_order + SYMTAB_COMMAND_FORMAT)])
            self.f.seek(cmd_start + cmdsize)

        if not symtab:
            return symhash_dict

        symoff = symtab[2]
        nsyms = symtab[3]
        stroff = symtab[4]
        strsize = symtab[5]

        self.f.seek(stroff)
        string_table = self.f.read(strsize)
        self.f.seek(symoff)
        if is_64_bit:
            nlist_fmt = byte_order + "IbbHQ"  # n_strx, n_type, n_sect, n_desc, n_value
            nlist_size = struct.calcsize(nlist_fmt)
        else:
            nlist_fmt = byte_order + "IbbHI"  # n_strx, n_type, n_sect, n_desc, n_value
            nlist_size = struct.calcsize(nlist_fmt)

        for idx in range(nsyms):
            self.f.seek(symoff + idx * nlist_size)
            entry = self.f.read(nlist_size)
            if len(entry) != nlist_size:
                continue
            if is_64_bit:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack(nlist_fmt, entry)
            else:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack(nlist_fmt, entry)
            # Skip STAB/debug symbols
            if n_type & N_STAB != 0:
                continue
            # Only external
            if not (n_type & N_EXT):
                continue
            # Only undefined
            if (n_type & N_TYPE) != N_UNDF:
                continue
            if n_strx == 0:
                continue
            str_offset = n_strx
            if str_offset < len(string_table):
                name = string_table[str_offset:string_table.find(b"\x00", str_offset)]
                if not name:
                    continue
                symbol_name = name.decode(errors="replace")
                sym_list.append(symbol_name)
        # Sort and hash
        sym_list = sorted(set(sym_list))
        symhash = md5(",".join(sym_list).encode()).hexdigest()
        # Compose entity string (like original: cputype filetype magic)
        cputype = self.header.get("cputype", "?")
        filetype = self.header.get("filetype", "?")
        magic_str = self.header.get("magic", "?")
        entity_string = f"{cputype} {filetype} {magic_str}"
        symhash_dict[entity_string] = symhash
        return symhash_dict

    def get_symhash(self):
        """Get the symhash for the current Mach-O entity (first/only arch,
            not supporting FAT files yet).

        Returns:
            symhash: the symhash of the Mach-O file.
        """
        d = self.get_symhash_dict()
        if d:
            return list(d.values())[0]
        return None
    
    def get_similarity_hashes(self):
        """Get the similarity hashes of the Mach-O file.

        This method is used to get different available similarity hashes of
        the Mach-O file. This is inspired by the "macho-similarity" tool
        from Greg Lesnewich (@greglesnewich)

        Returns:
            similarity_hashes: A dictionary containing the similarity hashes
                of the Mach-O file. Currently implemented are: dylib_hash,
                import_hash, export_hash, and symhash.
        """
        similarity_hashes = {}

        similarity_hashes["dylib_hash"] = self.get_dylib_hash()
        similarity_hashes["import_hash"] = self.get_import_hash()
        similarity_hashes["export_hash"] = self.get_export_hash()
        similarity_hashes["symhash"] = self.get_symhash()

        return similarity_hashes

# --- CLI Helper Functions ---
import argparse

def print_dict(d):
    for k, v in d.items():
        if isinstance(v, list):
            print(f"\t{k + ':':<13}")
            for item in v:
                print(f"\t\t{item}")
        else:
            if v is not None:
                print(f"\t{k + ':':<13}{v}")

def print_list(l):
    for i in l:
        print(f"\t{i}")

def print_list_dict(l):
    for d in l:
        for k, v in d.items():
            print(f"\t{k + ':':<13}{v}")

def print_list_dict_as_table(dict_list):
    if not dict_list:
        print("Empty list provided.")
        return
    headers = list(dict_list[0].keys())
    widths = {
        key: max(max(len(str(d.get(key, ""))) for d in dict_list), len(key))
        for key in headers
    }
    header_row = " ".join(key.upper().ljust(widths[key]) for key in headers)
    print(f"\t{header_row}")
    print("\t" + ("-" * len(header_row)))
    for item in dict_list:
        row = " ".join(str(item.get(key, "")).ljust(widths[key]) for key in headers)
        print(f"\t{row}")

# --- CLI Main Entrypoint ---
def main():
    parser = argparse.ArgumentParser(description="Parse Mach-O file structures.")
    parser.add_argument(
        "-f", "--file", type=str, help="Path to the file to be parsed", required=True
    )
    parser.add_argument(
        "-a", "--all", action="store_true", help="Print all info about the file"
    )
    parser.add_argument(
        "-g", "--general_info", action="store_true", help="Print general info about the file"
    )
    parser.add_argument(
        "-hd", "--header", action="store_true", help="Print Mach-O header info"
    )
    parser.add_argument(
        "-l",
        "--load_cmd_t",
        action="store_true",
        help="Print Load Command Table and Command list",
    )
    parser.add_argument(
        "-sg", "--segments", action="store_true", help="Print File Segments info"
    )
    parser.add_argument(
        "-d",
        "--dylib",
        action="store_true",
        help="Print Dylib Command Table and Dylib list",
    )
    parser.add_argument(
        "-i", "--imports", action="store_true", help="Print imported symbols"
    )
    parser.add_argument(
        "-e", "--exports", action="store_true", help="Print exported symbols"
    )
    parser.add_argument(
        "-sm", "--similarity", action="store_true", help="Print similarity hashes"
    )

    args = parser.parse_args()
    file_path = args.file
    filename = os.path.basename(file_path)

    macho = MachO(file_path=file_path)
    macho.parse()

    if args.all or args.general_info:
        print("\n[General File Info]")
        print_dict(macho.general_info)

    if args.all or args.header:
        print("\n[Mach-O Header]")
        print_dict(macho.header)

    if args.all or args.load_cmd_t:
        print("\n[Load Cmd table]")
        print_list(macho.load_commands)
        print("\n[Load Commands]")
        print_list(sorted(macho.load_commands_set))

    if args.all or args.segments:
        print("\n[File Segments]")
        print_list_dict_as_table(macho.segments)

    if args.all or args.dylib:
        print("\n[Dylib Commands]")
        print_list_dict_as_table(macho.dylib_commands)
        print("\n[Dylib Names]")
        print_list(macho.dylib_names)

    if args.all or args.imports:
        print("\n[Imported Functions]")
        if macho.imported_functions:
            print_dict(macho.imported_functions)
        else:
            print("\tNo imported functions found")

    if args.all or args.exports:
        print("\n[Exported Functions]")
        if macho.exported_symbols:
            print_dict(macho.exported_symbols)
        else:
            print("\tNo exported symbols found")

    if args.all or args.similarity:
        print("\n[Similarity Hashes]")
        print_dict(macho.get_similarity_hashes())

if __name__ == "__main__":
    main()
