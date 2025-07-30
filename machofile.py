#!/usr/bin/python

"""machofile, Mach-O file reader module

The Mach-O file format is the executable file format used 
by macOS, iOS, watchOS, and tvOS.

Inspired by pefile, this module aims to provide a similar 
capability but for Mach-O binaries instead, with a focus on 
malware analysis and reverse engineering. The basic structures 
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

__author__ = "Pasquale Stirparo"
__version__ = "2025.07.30"
__contact__ = "pstirparo@threatresearch.ch"

from hashlib import sha256
from hashlib import md5
from hashlib import sha1
import struct
import os
import io
from typing import Counter
import math
import json


# === EXCEPTION CLASSES ===
class MachOError(Exception):
    """Base exception for Mach-O parsing errors."""
    pass

class MachOParseError(MachOError):
    """Exception raised when parsing fails."""
    pass

class MachOValidationError(MachOError):
    """Exception raised when validation fails."""
    pass

class MachOSecurityError(MachOError):
    """Exception raised when security limits are exceeded."""
    pass


# === SAFETY CONSTANTS ===
MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB limit
MAX_LOAD_COMMANDS = 10000  # Reasonable upper limit for load commands
MAX_SYMBOL_NAME_LENGTH = 1000  # Maximum reasonable symbol name length
MAX_TRIE_DEPTH = 100  # Maximum trie traversal depth
MAX_TRIE_ITERATIONS = 50000  # Maximum trie parsing iterations
ENTROPY_SAMPLE_SIZE = 64 * 1024  # 64KB sample for large segments
MIN_MACHO_SIZE = 28  # Minimum valid Mach-O file size


def two_way_dict(pairs):
    return dict([(e[1], e[0]) for e in pairs] + pairs)


# === MACH-O CONSTANTS (keeping all existing constants) ===
# Mach-O header formats
MACHO_HEADER_FORMAT_32 = "IiiIIII"
MACHO_HEADER_FORMAT_64 = "IiiIIIII"
LOAD_COMMAND_FORMAT = "II"
SEGMENT_COMMAND_FORMAT_32 = "16sIIIIIIII"
SEGMENT_COMMAND_FORMAT_64 = "16sQQQQIIII"
DYLIB_COMMAND_FORMAT = "IIII"
DYLIB_INFO_FORMAT = "IIIIIIIIII"
SYMTAB_COMMAND_FORMAT = "IIIIII"
DYSYMTAB_COMMAND_FORMAT = "IIIIIIIIIIIIIIIIII"
EXPORT_TRIE_FORMAT = "II"
VERSION_COMMAND_FORMAT = "II"
MAIN_COMMAND_FORMAT = "QQ"
CODE_SIGNATURE_FORMAT = "II"

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
    ("CPU_SUBTYPE_X86_ALL", 0x3), # Generic x86 compatibility (both 32-bit and 64-bit)
    ("CPU_SUBTYPE_ARM_ALL", 0x0),
    ("CPU_SUBTYPE_ARM64E", 0x2),
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
    ("CPU_SUBTYPE_ARM64_V8", 0x1),
    ("CPU_SUBTYPE_ARM64E", 0x80000002),  # ARM64E with capability bits set
]

CPU_SUBTYPE_MAP = two_way_dict(cpu_subtypes)

# ARM64E capability bit constants from Apple source
CPU_SUBTYPE_MASK = 0xff000000  # mask for feature flags
CPU_SUBTYPE_LIB64 = 0x80000000  # 64 bit libraries (also used for PtrAuth ABI on ARM64E)

# ARM64E capability bit constants
CPU_SUBTYPE_ARM64E_VERSIONED_PTRAUTH_ABI_MASK = 0x80000000  # Bit 63: Versioned PtrAuth ABI (same as LIB64)
CPU_SUBTYPE_ARM64E_KERNEL_PTRAUTH_ABI_MASK = 0x40000000     # Bit 62: Kernel PtrAuth ABI
CPU_SUBTYPE_ARM64E_PTRAUTH_MASK = 0x0f000000                # Bits [59:56]: 4-bit PtrAuth ABI version

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

# Code signature magic constants
CSMAGIC_REQUIREMENT = 0xFADE0C00
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xFADE0B02
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_DETACHED_SIGNATURE = 0xFADE0CC1
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT = 0xFADE8181

# Code signature slot types
CSSLOT_CODEDIRECTORY = 0
CSSLOT_INFOSLOT = 1
CSSLOT_REQUIREMENTS = 2
CSSLOT_RESOURCEDIR = 3
CSSLOT_APPLICATION = 4
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_LAUNCH_CONSTRAINT_SELF = 8
CSSLOT_LAUNCH_CONSTRAINT_PARENT = 9
CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE = 10
CSSLOT_LIBRARY_CONSTRAINT = 11

# Alternate code directories
CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
CSSLOT_ALTERNATE_CODEDIRECTORY_MAX = 5
CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX

# Signature slots
CSSLOT_SIGNATURESLOT = 0x10000
CSSLOT_IDENTIFICATIONSLOT = 0x10001
CSSLOT_TICKETSLOT = 0x10002

# Code signature hash algorithms
CS_HASHTYPE_SHA1 = 1
CS_HASHTYPE_SHA256 = 2
CS_HASHTYPE_SHA256_TRUNCATED = 3
CS_HASHTYPE_SHA384 = 4

# Hash lengths
CS_SHA1_LEN = 20
CS_SHA256_LEN = 32
CS_SHA256_TRUNCATED_LEN = 20
CS_SHA384_LEN = 48
CS_CDHASH_LEN = 20
CS_HASH_MAX_SIZE = 48

# Code signature support flags
CS_SUPPORTSSCATTER = 0x20100
CS_SUPPORTSTEAMID = 0x20200
CS_SUPPORTSCODELIMIT64 = 0x20300
CS_SUPPORTSEXECSEG = 0x20400
CS_SUPPORTSRUNTIME = 0x20500
CS_SUPPORTSLINKAGE = 0x20600

# Mach-O dynamic linker constant
LC_REQ_DYLD = 0x80000000

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
    ("LC_LOAD_WEAK_DYLIB", 0x18 | LC_REQ_DYLD),
    ("LC_SEGMENT_64", 0x19),
    ("LC_ROUTINES_64", 0x1A),
    ("LC_UUID", 0x1B),
    ("LC_RPATH", 0x1C | LC_REQ_DYLD),
    ("LC_CODE_SIGNATURE", 0x1D),
    ("LC_SEGMENT_SPLIT_INFO", 0x1E),
    ("LC_REEXPORT_DYLIB", 0x1F | LC_REQ_DYLD),
    ("LC_LAZY_LOAD_DYLIB", 0x20),
    ("LC_ENCRYPTION_INFO", 0x21),
    ("LC_DYLD_INFO", 0x22),
    ("LC_DYLD_INFO_ONLY", 0x22 | LC_REQ_DYLD),
    ("LC_LOAD_UPWARD_DYLIB", 0x23 | LC_REQ_DYLD),
    ("LC_VERSION_MIN_MACOSX", 0x24),
    ("LC_VERSION_MIN_IPHONEOS", 0x25),
    ("LC_FUNCTION_STARTS", 0x26),
    ("LC_DYLD_ENVIRONMENT", 0x27),
    ("LC_MAIN", 0x28 | LC_REQ_DYLD),
    ("LC_DATA_IN_CODE", 0x29),
    ("LC_SOURCE_VERSION", 0x2A),
    ("LC_DYLIB_CODE_SIGN_DRS", 0x2B),
    ("LC_ENCRYPTION_INFO_64", 0x2C),
    ("LC_LINKER_OPTIONS", 0x2D),
    ("LC_LINKER_OPTIMIZATION_HINT", 0x2E),
    ("LC_VERSION_MIN_TVOS", 0x2F),
    ("LC_VERSION_MIN_WATCHOS", 0x30),
    ("LC_NOTE", 0x31),
    ("LC_BUILD_VERSION", 0x32),
    ("LC_DYLD_EXPORTS_TRIE", 0x33 | LC_REQ_DYLD),
    ("LC_DYLD_CHAINED_FIXUPS", 0x34 | LC_REQ_DYLD),
]

LOAD_COMMAND_TYPES = two_way_dict(load_command_types)

dylib_command_types = [
    ("LC_ID_DYLIB", 0xD),
    ("LC_LOAD_DYLIB", 0xC),
    ("LC_LOAD_WEAK_DYLIB", 0x18),
]

DYLIB_CMD_TYPES = two_way_dict(dylib_command_types)

PLATFORM_MAP = {
    LOAD_COMMAND_TYPES["LC_VERSION_MIN_MACOSX"]: "macOS",
    LOAD_COMMAND_TYPES["LC_VERSION_MIN_IPHONEOS"]: "iOS", 
    LOAD_COMMAND_TYPES["LC_VERSION_MIN_TVOS"]: "tvOS",
    LOAD_COMMAND_TYPES["LC_VERSION_MIN_WATCHOS"]: "watchOS",
}


# === HELPER FUNCTIONS ===
def _validate_file_path(file_path):
    """Validate file path and return absolute path."""
    if not file_path:
        raise ValueError("File path cannot be empty")
    
    abs_path = os.path.abspath(file_path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"File not found: {abs_path}")
    
    return abs_path

def _validate_file_size(file_size):
    """Validate file size against security limits."""
    if file_size < MIN_MACHO_SIZE:
        raise MachOValidationError(f"File too small to be valid Mach-O: {file_size} bytes")
    
    if file_size > MAX_FILE_SIZE:
        raise MachOSecurityError(f"File too large: {file_size} bytes (limit: {MAX_FILE_SIZE})")

def _safe_read_struct(f, fmt, data_name="data"):
    """Safely read struct data with bounds checking."""
    try:
        size = struct.calcsize(fmt)
        data = f.read(size)
        if len(data) != size:
            raise MachOParseError(f"Insufficient {data_name}: expected {size} bytes, got {len(data)}")
        return struct.unpack(fmt, data)
    except struct.error as e:
        raise MachOParseError(f"Failed to parse {data_name}: {e}")

def _safe_string_from_table(string_table, offset, max_length=MAX_SYMBOL_NAME_LENGTH):
    """Safely extract string from string table with bounds checking."""
    if not string_table or offset >= len(string_table):
        return None
    
    # Find null terminator
    null_pos = string_table.find(b'\x00', offset)
    if null_pos == -1:
        null_pos = len(string_table)
    
    # Limit string length for security
    end_pos = min(null_pos, offset + max_length)
    
    try:
        return string_table[offset:end_pos].decode('utf-8', errors='replace')
    except (UnicodeDecodeError, MemoryError):
        return None

def _validate_offset_and_size(offset, size, file_size, data_name="data"):
    """Validate that offset and size are within file bounds."""
    if offset < 0 or size < 0:
        raise MachOValidationError(f"Invalid {data_name}: negative offset or size")
    
    if offset + size > file_size:
        raise MachOValidationError(f"Invalid {data_name}: extends beyond file (offset={offset}, size={size}, file_size={file_size})")


class UniversalMachO:
    """A Universal/FAT Mach-O binary representation with enhanced error handling."""
    
    def __init__(self, file_path=None, data=None):
        if file_path is None and data is None:
            raise ValueError("Must supply either file_path or data")
        elif file_path is not None:
            self.file_path = _validate_file_path(file_path)
            file_size = os.path.getsize(self.file_path)
            _validate_file_size(file_size)
            
            with open(self.file_path, "rb") as fh:
                self.data = fh.read()
        else:
            self.data = data
            self.file_path = None
            _validate_file_size(len(self.data))

        self.f = io.BytesIO(self.data)
        
        # Check if this is a FAT binary
        self.is_fat = self._is_fat_binary()
        
        if self.is_fat:
            self.architectures = {}
            self._parse_fat_binary()
        else:
            # Single architecture - create single MachO instance
            self.macho = MachO(data=self.data)
            self.macho.file_path = self.file_path
    
    def _is_fat_binary(self):
        """Check if the binary is a FAT/Universal binary."""
        if len(self.data) < 4:
            return False
        
        try:
            magic = struct.unpack(">I", self.data[:4])[0]
            return magic in {FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64}
        except struct.error:
            return False
    
    def _parse_fat_binary(self):
        """Parse FAT binary header and extract individual architectures."""
        self.f.seek(0)
        
        try:
            # Read FAT header with validation
            magic = struct.unpack(">I", self.f.read(4))[0]
            nfat_arch = struct.unpack(">I", self.f.read(4))[0]
            
            # Determine if we need to swap bytes
            swap_bytes = magic in {FAT_CIGAM, FAT_CIGAM_64}
            endian = "<" if swap_bytes else ">"
            
            if swap_bytes:
                nfat_arch = struct.unpack("<I", struct.pack(">I", nfat_arch))[0]
            
            # Validate number of architectures
            if nfat_arch > 50:  # Reasonable upper limit
                raise MachOValidationError(f"Too many architectures in FAT binary: {nfat_arch}")
            
            # Read FAT arch entries
            for i in range(nfat_arch):
                if self.f.tell() + 20 > len(self.data):
                    raise MachOParseError(f"FAT arch entry {i} extends beyond file")
                
                fat_arch_data = self.f.read(20)
                
                if swap_bytes:
                    cputype, cpusubtype, offset, size, align = struct.unpack("<5I", fat_arch_data)
                else:
                    cputype, cpusubtype, offset, size, align = struct.unpack(">5I", fat_arch_data)
                
                # Validate architecture data
                _validate_offset_and_size(offset, size, len(self.data), f"architecture {i}")
                
                # Extract architecture name
                arch_name = self._get_arch_name(cputype, cpusubtype)
                
                # Extract Mach-O data for this architecture
                macho_data = self.data[offset:offset + size]
                
                # Create MachO instance for this architecture
                try:
                    macho_instance = MachO(data=macho_data)
                    macho_instance.file_path = self.file_path
                    self.architectures[arch_name] = macho_instance
                except MachOError:
                    # Skip invalid architectures but continue with others
                    continue
                    
        except (struct.error, IOError) as e:
            raise MachOParseError(f"Failed to parse FAT binary: {e}")
    
    def _get_arch_name(self, cputype, cpusubtype):
        """Get architecture name from CPU type and subtype."""
        base_name = CPU_TYPE_MAP.get(cputype, f"cpu_{cputype}")

        # Mask off high bits that may be set for certain subtypes
        clean_subtype = cpusubtype & 0x00FFFFFF
        
        # Add subtype info for ARM variants
        if cputype == CPU_TYPE_ARM64:
            if clean_subtype == 0:
                return "arm64"
            elif clean_subtype == 2:
                return "arm64e"
            else:
                return f"arm64_{clean_subtype}"
        
        return base_name
    
    def parse(self):
        """Parse the Mach-O file(s)."""
        if self.is_fat:
            for arch_name, macho_instance in self.architectures.items():
                try:
                    macho_instance.parse()
                except MachOError as e:
                    # Log error but continue with other architectures
                    print(f"Warning: Failed to parse architecture {arch_name}: {e}")
        else:
            self.macho.parse()
    
    def get_architectures(self):
        """Get list of architectures in this binary."""
        if self.is_fat:
            return list(self.architectures.keys())
        else:
            return ["single_arch"]
    
    def get_macho_for_arch(self, arch_name):
        """Get MachO instance for specific architecture."""
        if self.is_fat:
            return self.architectures.get(arch_name)
        else:
            available_archs = self.get_architectures()
            if arch_name in available_archs:
                return self.macho
            return None
    
    # Delegation methods with error handling
    def get_general_info(self, arch=None):
        """Get general info. If arch specified, return for that arch only."""
        if arch:
            macho_instance = self.get_macho_for_arch(arch)
            return macho_instance.get_general_info() if macho_instance else None
        
        if self.is_fat:
            return {arch: macho.get_general_info() 
                   for arch, macho in self.architectures.items()}
        else:
            return self.macho.get_general_info()
    
    def get_macho_header(self, arch=None):
        """Get Mach-O header. If arch specified, return for that arch only."""
        if arch:
            macho_instance = self.get_macho_for_arch(arch)
            return macho_instance.get_macho_header() if macho_instance else None
        
        if self.is_fat:
            return {arch: macho.get_macho_header() 
                   for arch, macho in self.architectures.items()}
        else:
            return self.macho.get_macho_header()
    
    def get_imported_functions(self, arch=None):
        """Get imported functions. If arch specified, return for that arch only."""
        if arch:
            macho_instance = self.get_macho_for_arch(arch)
            return macho_instance.get_imported_functions() if macho_instance else None
        
        if self.is_fat:
            return {arch: macho.get_imported_functions() 
                   for arch, macho in self.architectures.items()}
        else:
            return self.macho.get_imported_functions()
    
    def get_exported_symbols(self, arch=None):
        """Get exported symbols. If arch specified, return for that arch only."""
        if arch:
            macho_instance = self.get_macho_for_arch(arch)
            return macho_instance.get_exported_symbols() if macho_instance else None
        
        if self.is_fat:
            return {arch: macho.get_exported_symbols() 
                   for arch, macho in self.architectures.items()}
        else:
            return self.macho.get_exported_symbols()
    
    def get_similarity_hashes(self, arch=None):
        """Get similarity hashes. If arch specified, return for that arch only."""
        if arch:
            macho_instance = self.get_macho_for_arch(arch)
            return macho_instance.get_similarity_hashes() if macho_instance else None
        
        if self.is_fat:
            return {arch: macho.get_similarity_hashes() 
                   for arch, macho in self.architectures.items()}
        else:
            return self.macho.get_similarity_hashes()
    
    # Attribute delegation for CLI compatibility with error handling
    @property
    def load_commands(self):
        if self.is_fat:
            return {arch_name: getattr(macho_instance, 'load_commands', None) 
                   for arch_name, macho_instance in self.architectures.items()}
        else:
            return getattr(self.macho, 'load_commands', None)
    
    @property  
    def load_commands_set(self):
        if self.is_fat:
            return {arch_name: getattr(macho_instance, 'load_commands_set', None) 
                   for arch_name, macho_instance in self.architectures.items()}
        else:
            return getattr(self.macho, 'load_commands_set', None)
    
    @property
    def segments(self):
        if self.is_fat:
            return {arch_name: getattr(macho_instance, 'segments', None) 
                   for arch_name, macho_instance in self.architectures.items()}
        else:
            return getattr(self.macho, 'segments', None)
    
    @property
    def dylib_commands(self):
        if self.is_fat:
            return {arch_name: getattr(macho_instance, 'dylib_commands', None) 
                   for arch_name, macho_instance in self.architectures.items()}
        else:
            return getattr(self.macho, 'dylib_commands', None)
    
    @property
    def dylib_names(self):
        if self.is_fat:
            return {arch_name: getattr(macho_instance, 'dylib_names', None) 
                   for arch_name, macho_instance in self.architectures.items()}
        else:
            return getattr(self.macho, 'dylib_names', None)
    
    @property
    def uuid(self):
        if self.is_fat:
            return {arch_name: getattr(macho_instance, 'uuid', None) 
                   for arch_name, macho_instance in self.architectures.items()}
        else:
            return getattr(self.macho, 'uuid', None)
    
    @property
    def entry_point(self):
        if self.is_fat:
            return {arch_name: getattr(macho_instance, 'entry_point', None) 
                   for arch_name, macho_instance in self.architectures.items()}
        else:
            return getattr(self.macho, 'entry_point', None)
    
    @property
    def version_info(self):
        if self.is_fat:
            return {arch_name: getattr(macho_instance, 'version_info', None) 
                   for arch_name, macho_instance in self.architectures.items()}
        else:
            return getattr(self.macho, 'version_info', None)
    
    @property
    def code_signature_info(self):
        if self.is_fat:
            return {arch_name: getattr(macho_instance, 'code_signature_info', None) 
                   for arch_name, macho_instance in self.architectures.items()}
        else:
            return getattr(self.macho, 'code_signature_info', None)
    
    @property
    def imported_functions(self):
        if self.is_fat:
            return {arch_name: getattr(macho_instance, 'imported_functions', None) 
                   for arch_name, macho_instance in self.architectures.items()}
        else:
            return getattr(self.macho, 'imported_functions', None)
    
    @property
    def exported_symbols(self):
        if self.is_fat:
            return {arch_name: getattr(macho_instance, 'exported_symbols', None) 
                   for arch_name, macho_instance in self.architectures.items()}
        else:
            return getattr(self.macho, 'exported_symbols', None)


class MachO:
    """A Mach-O representation with enhanced error handling and validation."""

    def __init__(self, file_path=None, data=None):
        if file_path is None and data is None:
            raise ValueError("Must supply either file_path or data")
        elif file_path is not None:
            self.file_path = _validate_file_path(file_path)
            file_size = os.path.getsize(self.file_path)
            _validate_file_size(file_size)
            
            with open(self.file_path, "rb") as fh:
                self.data = fh.read()
        else:
            self.file_path = None
            self.data = data
            _validate_file_size(len(self.data))

        self.f = io.BytesIO(self.data)

        # Initialize caches for performance
        self._string_table_cache = None
        self._symbol_table_cache = None
        self._header_info_cache = None

        # Initialize attributes
        self.general_info = {}
        self.header = {}
        self.load_commands = []
        self.load_commands_set = set()
        self.segments = []
        self.dylib_commands = []
        self.dylib_names = []
        self.dyld_info = {}
        self.dyld_export_trie = {}
        self.uuid = None
        self.entry_point = None
        self.version_info = None
        self.code_signature_data = None
        self.code_signature_info = None
        self.imported_functions = {}
        self.exported_symbols = {}

    def _get_header_info(self):
        """Get and cache basic header information."""
        if self._header_info_cache:
            return self._header_info_cache
        
        try:
            self.f.seek(0)
            if len(self.data) < 4:
                raise MachOValidationError("File too small for magic number")
            
            magic = struct.unpack("I", self.f.read(4))[0]
            is_64_bit = magic in {MH_MAGIC_64, MH_CIGAM_64}
            byte_order = ">" if magic in {MH_CIGAM, MH_CIGAM_64} else "<"
            
            # Read number of commands with validation
            self.f.seek(16)  # Skip to ncmds field
            if len(self.data) < 20:
                raise MachOValidationError("File too small for header")
            
            ncmds = struct.unpack(byte_order + "I", self.f.read(4))[0]
            
            # Validate number of load commands
            if ncmds > MAX_LOAD_COMMANDS:
                raise MachOSecurityError(f"Too many load commands: {ncmds}")
            
            self._header_info_cache = (magic, byte_order, is_64_bit, ncmds)
            return self._header_info_cache
            
        except (struct.error, IOError) as e:
            raise MachOParseError(f"Failed to read header info: {e}")

    def _get_symtab_info(self):
        """Get symbol table information with caching."""
        if hasattr(self, '_symtab_info_cache'):
            return self._symtab_info_cache
        
        magic, byte_order, is_64_bit, ncmds = self._get_header_info()
        
        # Skip to load commands
        header_size = 32 if is_64_bit else 28
        self.f.seek(header_size)
        
        for _ in range(ncmds):
            cmd_start = self.f.tell()
            if cmd_start + 8 > len(self.data):
                break
                
            try:
                cmd, cmdsize = _safe_read_struct(self.f, byte_order + "II", "load command header")
                
                if cmd == LOAD_COMMAND_TYPES["LC_SYMTAB"]:
                    if cmdsize < 24:  # Size of LC_SYMTAB structure
                        continue
                    
                    # Read remaining fields
                    symoff, nsyms, stroff, strsize = _safe_read_struct(
                        self.f, byte_order + "IIII", "symtab command"
                    )
                    
                    # Validate symbol table data
                    _validate_offset_and_size(symoff, nsyms * (16 if is_64_bit else 12), 
                                            len(self.data), "symbol table")
                    _validate_offset_and_size(stroff, strsize, len(self.data), "string table")
                    
                    self._symtab_info_cache = {
                        'symoff': symoff,
                        'nsyms': nsyms,
                        'stroff': stroff,
                        'strsize': strsize
                    }
                    return self._symtab_info_cache
                
                # Move to next command
                self.f.seek(cmd_start + cmdsize)
                
            except (MachOError, struct.error):
                # Skip malformed commands
                continue
        
        self._symtab_info_cache = None
        return None

    def _get_string_table(self):
        """Get and cache string table."""
        if self._string_table_cache is not None:
            return self._string_table_cache
        
        symtab_info = self._get_symtab_info()
        if not symtab_info:
            return None
        
        try:
            self.f.seek(symtab_info['stroff'])
            self._string_table_cache = self.f.read(symtab_info['strsize'])
            return self._string_table_cache
        except (IOError, MemoryError):
            return None

    def parse(self):
        """Parse a Mach-O file with enhanced error handling."""
        try:
            self.general_info = self.get_general_info()
            self.header = self.get_macho_header()

            # Consolidated load command parsing
            (self.load_commands, self.load_commands_set, self.segments, 
            self.dylib_commands, self.dylib_names, self.dyld_info, 
            self.dyld_export_trie, self.uuid, self.entry_point, 
            self.version_info, self.code_signature_data) = self.parse_all_load_commands()

            self.code_signature_info = self.parse_code_signature()
            self.imported_functions = self.get_imported_functions()
            self.exported_symbols = self.get_exported_symbols()
            
        except MachOError:
            raise
        except Exception as e:
            raise MachOParseError(f"Unexpected error during parsing: {e}")

    def decode_cpusubtype(self, cputype, cpusubtype_value):
        """Fixed CPU subtype decoding with proper ARM64 handling."""
        mask = 0xFFFFFFFF
        cpusubtype_value = cpusubtype_value & mask
        
        # Handle ARM64 architectures first (before exact match check)
        if cputype == CPU_TYPE_ARM64:
            # Extract base subtype and capability bits using correct masks
            base_subtype = cpusubtype_value & ~CPU_SUBTYPE_MASK
            capability_bits = cpusubtype_value & CPU_SUBTYPE_MASK
            
            # Check if we have a mapping for the base subtype
            if base_subtype in CPU_SUBTYPE_MAP:
                base_name = CPU_SUBTYPE_MAP[base_subtype].replace("CPU_SUBTYPE_", "")
                
                # For ARM64E, decode capability bits with meaningful information
                if base_subtype == 2 and capability_bits:  # CPU_SUBTYPE_ARM64E with capabilities
                    capability_info = []
                    
                    # Check for Versioned PtrAuth ABI (bit 63)
                    if cpusubtype_value & CPU_SUBTYPE_ARM64E_VERSIONED_PTRAUTH_ABI_MASK:
                        capability_info.append("Versioned PtrAuth")
                        
                        # Extract PtrAuth ABI version (bits 59-56)
                        ptrauth_version = (cpusubtype_value & CPU_SUBTYPE_ARM64E_PTRAUTH_MASK) >> 24
                        if ptrauth_version:
                            capability_info.append(f"v{ptrauth_version}")
                    
                    # Check for Kernel PtrAuth ABI (bit 62)
                    if cpusubtype_value & CPU_SUBTYPE_ARM64E_KERNEL_PTRAUTH_ABI_MASK:
                        capability_info.append("Kernel PtrAuth")
                    
                    if capability_info:
                        return f"{base_name} ({' '.join(capability_info)})"
                    else:
                        # Fallback to hex if we have unknown capability bits
                        return f"{base_name} (0x{cpusubtype_value:X})"
                
                return base_name
        
        # Exact match using CPU_SUBTYPE_MAP
        if cpusubtype_value in CPU_SUBTYPE_MAP:
            base_name = CPU_SUBTYPE_MAP[cpusubtype_value].replace("CPU_SUBTYPE_", "")
            return base_name
        
        # Handle x86/x86_64 LIB64 flag (0x80000000)
        if (cputype in [CPU_TYPE_I386, CPU_TYPE_X86_64] and 
            cpusubtype_value & CPU_SUBTYPE_LIB64):
            # Extract base subtype and LIB64 flag
            base_subtype = cpusubtype_value & ~CPU_SUBTYPE_LIB64
            if base_subtype in CPU_SUBTYPE_MAP:
                base_name = CPU_SUBTYPE_MAP[base_subtype].replace("CPU_SUBTYPE_", "")
                return f"{base_name} (LIB64)"
        
        # If no match found, return the numeric value
        return str(cpusubtype_value)

    def decode_flags(self, flags_value):
        """Decode flags with validation."""
        if not isinstance(flags_value, int) or flags_value < 0:
            return str(flags_value)
        
        decoded_flags = []
        for flag, flag_name in FLAGS_MAP.items():
            if flags_value & flag:
                # Remove 'MH_' prefix if present
                if flag_name.startswith('MH_'):
                    decoded_flags.append(flag_name[3:])
                else:
                    decoded_flags.append(flag_name)
        return ", ".join(decoded_flags) if decoded_flags else str(flags_value)

    # --- Header Formatting Helper Functions ---
    def format_magic_value(self, magic_val):
        """Format magic value for human-readable display."""
        magic_str = MAGIC_MAP.get(magic_val, magic_val)
        if isinstance(magic_str, str):
            return f"{magic_str}, 0x{magic_val:08X}"
        else:
            return f"0x{magic_val:08X}"
    
    def format_file_type(self, filetype):
        """Format file type for human-readable display."""
        filetype_str = MACHO_FILETYPE.get(filetype, f"UNKNOWN_0x{filetype:x}")
        if filetype_str.startswith('MH_'):
            return filetype_str[3:]
        return filetype_str
    
    def format_header_for_display(self, raw_header):
        """Format raw header dictionary for human-readable display."""
        if not isinstance(raw_header, dict):
            return raw_header
        
        return {
            "magic": self.format_magic_value(raw_header.get("magic", 0)),
            "cputype": CPU_TYPE_MAP.get(raw_header.get("cputype", 0), raw_header.get("cputype", 0)),
            "cpusubtype": self.decode_cpusubtype(raw_header.get("cputype", 0), raw_header.get("cpusubtype", 0)),
            "filetype": self.format_file_type(raw_header.get("filetype", 0)),
            "ncmds": raw_header.get("ncmds", 0),
            "sizeofcmds": raw_header.get("sizeofcmds", 0),
            "flags": self.decode_flags(raw_header.get("flags", 0)),
        }
    
    def format_load_command(self, cmd_value):
        """Format load command for human-readable display."""
        return LOAD_COMMAND_TYPES.get(cmd_value, f"UNKNOWN_0x{cmd_value:x}")
    
    def format_load_commands_for_display(self, raw_load_commands):
        """Format raw load commands list for human-readable display."""
        if not raw_load_commands:
            return raw_load_commands
        return [
            {
                "cmd": self.format_load_command(lc.get("cmd", 0)),
                "cmdsize": lc.get("cmdsize", 0)
            }
            for lc in raw_load_commands
        ]
    
    def format_version_to_string(self, version_int):
        """Convert version number to readable format (major.minor.patch)."""
        if not isinstance(version_int, int):
            return str(version_int)
        
        major = (version_int >> 16) & 0xFFFF
        minor = (version_int >> 8) & 0xFF
        patch = version_int & 0xFF
        return f"{major}.{minor}.{patch}"
    
    def format_platform_name(self, platform_cmd):
        """Format platform command to readable name."""
        return PLATFORM_MAP.get(platform_cmd, f"Unknown (0x{platform_cmd:x})")
    
    def format_version_info_for_display(self, raw_version_info):
        """Format raw version info for human-readable display."""
        if not raw_version_info:
            return raw_version_info
        return {
            'platform': self.format_platform_name(raw_version_info.get('platform_cmd', 0)),
            'min_version': self.format_version_to_string(raw_version_info.get('min_version', 0)),
            'sdk_version': self.format_version_to_string(raw_version_info.get('sdk_version', 0))
        }

    def calculate_entropy(self, data):
        """Calculate the entropy of a chunk of data with improved error handling."""
        if not data:
            return 0.0

        try:
            if isinstance(data, str):
                counts = Counter(data)
                data_len = len(data)
            else:
                occurences = Counter(bytearray(data))
                counts = occurences
                data_len = len(data)
            
            if data_len == 0:
                return 0.0
            
            entropy = 0.0
            for count in counts.values():
                p_x = float(count) / data_len
                if p_x > 0:  # Avoid log(0)
                    entropy -= p_x * math.log(p_x, 2)
            
            return entropy
            
        except (ValueError, OverflowError, MemoryError):
            return 0.0
        
    def _calculate_segment_entropy(self, offset, size):
        """Read segment data and calculate its entropy with improved safety."""
        if size <= 0:
            return 0.0
        
        # Validate offset and size
        if offset < 0 or offset + size > len(self.data):
            return 0.0
        
        try:
            # Limit entropy calculation for very large segments
            sample_size = min(size, ENTROPY_SAMPLE_SIZE)
            
            # Read segment data
            self.f.seek(offset)
            segment_data = self.f.read(sample_size)
            
            # Calculate entropy
            return self.calculate_entropy(segment_data)
            
        except (IOError, OSError, MemoryError):
            return 0.0
    
    def get_general_info(self):
        """Get general information about a Mach-O file."""
        if self.file_path is None:
            filename = "-"
        else:
            filename = os.path.basename(self.file_path)
        
        try:
            md5_hash = md5()
            sha256_hash = sha256()
            sha1_hash = sha1()
            md5_hash.update(self.data)
            sha1_hash.update(self.data)
            sha256_hash.update(self.data)

            info_dict = {
                "Filename": filename,
                "Filesize": len(self.data),
                "MD5": md5_hash.hexdigest(),
                "SHA1": sha1_hash.hexdigest(),
                "SHA256": sha256_hash.hexdigest(),
            }
            return info_dict
        except MemoryError:
            raise MachOSecurityError("File too large for hash calculation")

    def get_macho_header(self):
        """Get the Mach-O header with enhanced validation."""
        try:
            magic, byte_order, is_64_bit, _ = self._get_header_info()
            
            # Position to start of file for full header read
            self.f.seek(0)
            if is_64_bit:
                header_size = struct.calcsize(byte_order + MACHO_HEADER_FORMAT_64)
                if len(self.data) < header_size:
                    raise MachOValidationError("File too small for 64-bit header")
                
                header_data = self.f.read(header_size)
                header = struct.unpack(byte_order + MACHO_HEADER_FORMAT_64, header_data)
            else:
                header_size = struct.calcsize(byte_order + MACHO_HEADER_FORMAT_32)
                if len(self.data) < header_size:
                    raise MachOValidationError("File too small for 32-bit header")
                
                header_data = self.f.read(header_size)
                header = struct.unpack(byte_order + MACHO_HEADER_FORMAT_32, header_data)

            # Return values for mach-o header are all unsigned
            header_dict = {
                "magic": header[0] & 0xFFFFFFFF,
                "cputype": header[1] & 0xFFFFFFFF,
                "cpusubtype": header[2] & 0xFFFFFFFF,
                "filetype": header[3],
                "ncmds": header[4],
                "sizeofcmds": header[5],
                "flags": header[6] & 0xFFFFFFFF,
            }

            return header_dict
            
        except (struct.error, IOError) as e:
            raise MachOParseError(f"Failed to parse header: {e}")

    def parse_all_load_commands(self):
        """Parse all load commands with enhanced error handling and validation."""
        # Initialize return variables
        load_commands = []
        segments = []
        dylib_commands = []
        dylib_names = []
        dyld_info = None
        dyld_export_trie = None
        uuid = None
        entry_point = None
        version_info = None
        code_signature_data = None

        try:
            magic, byte_order, is_64_bit, ncmds = self._get_header_info()
            
            # Skip to load commands
            header_size = 32 if is_64_bit else 28
            self.f.seek(header_size)
            
            # Parse each load command with bounds checking
            for cmd_index in range(ncmds):
                cmd_start = self.f.tell()
                
                # Check if we have enough data for command header
                if cmd_start + 8 > len(self.data):
                    break
                
                try:
                    cmd, cmdsize = _safe_read_struct(self.f, byte_order + "II", f"load command {cmd_index} header")
                    
                    # Validate command size
                    if cmdsize < 8 or cmd_start + cmdsize > len(self.data):
                        # Skip malformed command
                        if cmd_start + cmdsize <= len(self.data):
                            self.f.seek(cmd_start + cmdsize)
                        continue
                    
                    # Store load command info
                    load_commands.append({"cmd": cmd, "cmdsize": cmdsize})
                    
                    # Process different command types
                    self._process_load_command(cmd, cmdsize, cmd_start, byte_order, is_64_bit,
                                             segments, dylib_commands, dylib_names, dyld_info,
                                             dyld_export_trie, uuid, entry_point, version_info,
                                             code_signature_data)
                    
                except (MachOError, struct.error) as e:
                    # Skip malformed commands but continue parsing
                    try:
                        self.f.seek(cmd_start + cmdsize)
                    except:
                        break
                    continue

        except MachOError:
            raise
        except Exception as e:
            raise MachOParseError(f"Failed to parse load commands: {e}")

        # Create load commands set
        load_commands_set = set(load_command["cmd"] for load_command in load_commands)
        
        return (load_commands, load_commands_set, segments, dylib_commands, 
                dylib_names, dyld_info, dyld_export_trie, uuid, entry_point, 
                version_info, code_signature_data)

    def _process_load_command(self, cmd, cmdsize, cmd_start, byte_order, is_64_bit,
                            segments, dylib_commands, dylib_names, dyld_info,
                            dyld_export_trie, uuid, entry_point, version_info,
                            code_signature_data):
        """Process a single load command - extracted from the main parsing method."""
        
        # Process segments (LC_SEGMENT or LC_SEGMENT_64)
        if (cmd == LOAD_COMMAND_TYPES["LC_SEGMENT"] or 
            cmd == LOAD_COMMAND_TYPES["LC_SEGMENT_64"]):
            
            segment = self._parse_segment_command(cmd_start, byte_order, is_64_bit)
            if segment:
                segments.append(segment)
        
        # Process dylib commands
        elif cmd in [LOAD_COMMAND_TYPES["LC_LOAD_DYLIB"], 
                    LOAD_COMMAND_TYPES["LC_ID_DYLIB"],
                    LOAD_COMMAND_TYPES["LC_LOAD_WEAK_DYLIB"],
                    LOAD_COMMAND_TYPES["LC_REEXPORT_DYLIB"]]:
                    
            dylib = self._parse_dylib_command(cmd_start, cmdsize, byte_order)
            if dylib:
                dylib_commands.append(dylib)
                dylib_names.append(dylib['dylib_name'])
        
        # Process other command types...
        elif cmd in [LOAD_COMMAND_TYPES["LC_DYLD_INFO"], 
                    LOAD_COMMAND_TYPES["LC_DYLD_INFO_ONLY"]]:
            dyld_info = self._parse_dyld_info_command(cmd_start, byte_order)
        
        elif cmd == LOAD_COMMAND_TYPES["LC_DYLD_EXPORTS_TRIE"]:
            dyld_export_trie = self._parse_export_trie_command(cmd_start, byte_order)
        
        elif cmd == LOAD_COMMAND_TYPES["LC_UUID"]:
            uuid = self._parse_uuid_command(cmd_start)
        
        elif cmd == LOAD_COMMAND_TYPES["LC_MAIN"]:
            entry_point = self._parse_main_command(cmd_start, byte_order)
        
        elif cmd == LOAD_COMMAND_TYPES["LC_UNIXTHREAD"]:
            entry_point = self._parse_unixthread_command(cmd_start, cmdsize, byte_order, is_64_bit)
        
        elif cmd in [LOAD_COMMAND_TYPES["LC_VERSION_MIN_MACOSX"],
                    LOAD_COMMAND_TYPES["LC_VERSION_MIN_IPHONEOS"],
                    LOAD_COMMAND_TYPES["LC_VERSION_MIN_TVOS"],
                    LOAD_COMMAND_TYPES["LC_VERSION_MIN_WATCHOS"]]:
            version_info = self._parse_version_command(cmd_start, cmd, byte_order)
        
        elif cmd == LOAD_COMMAND_TYPES["LC_CODE_SIGNATURE"]:
            code_signature_data = self._parse_code_signature_command(cmd_start, byte_order)
        
        # Move to next command for all cases
        self.f.seek(cmd_start + cmdsize)

    def _parse_segment_command(self, cmd_start, byte_order, is_64_bit):
        """Parse segment command with validation."""
        try:
            self.f.seek(cmd_start + 8)  # Skip cmd and cmdsize
            
            if is_64_bit:
                segment_size = struct.calcsize(byte_order + SEGMENT_COMMAND_FORMAT_64)
                seg_data = self.f.read(segment_size)
                if len(seg_data) != segment_size:
                    return None
                    
                (segname, vaddr, vsize, offset, size, max_vm_protection,
                initial_vm_protection, nsectors, flags) = struct.unpack(
                    byte_order + SEGMENT_COMMAND_FORMAT_64, seg_data)
            else:
                segment_size = struct.calcsize(byte_order + SEGMENT_COMMAND_FORMAT_32)
                seg_data = self.f.read(segment_size)
                if len(seg_data) != segment_size:
                    return None
                    
                (segname, vaddr, vsize, offset, size, max_vm_protection,
                initial_vm_protection, nsectors, flags) = struct.unpack(
                    byte_order + SEGMENT_COMMAND_FORMAT_32, seg_data)
            
            # Validate segment data
            if offset > len(self.data) or (offset + size) > len(self.data):
                # Invalid segment, but don't fail entirely
                entropy = 0.0
            else:
                entropy = self._calculate_segment_entropy(offset, size)
            
            try:
                segname = segname.decode("utf-8").rstrip("\0")
            except UnicodeDecodeError:
                segname = segname.decode("utf-8", errors="replace").rstrip("\0")
            
            segment_dict = {
                "segname": segname,
                "vaddr": vaddr & (0xFFFFFFFFFFFFFFFF if is_64_bit else 0xFFFFFFFF),
                "vsize": vsize & (0xFFFFFFFFFFFFFFFF if is_64_bit else 0xFFFFFFFF),
                "offset": offset & (0xFFFFFFFFFFFFFFFF if is_64_bit else 0xFFFFFFFF),
                "size": size & (0xFFFFFFFFFFFFFFFF if is_64_bit else 0xFFFFFFFF),
                "max_vm_protection": max_vm_protection & 0xFFFFFFFF,
                "initial_vm_protection": initial_vm_protection & 0xFFFFFFFF,
                "nsects": nsectors,
                "flags": flags & 0xFFFFFFFF,
                "entropy": entropy,
            }
            return segment_dict
            
        except (struct.error, IOError):
            return None

    def _parse_dylib_command(self, cmd_start, cmdsize, byte_order):
        """Parse dylib command with validation."""
        try:
            self.f.seek(cmd_start + 8)  # Skip cmd and cmdsize
            
            dylib_size = struct.calcsize(byte_order + DYLIB_COMMAND_FORMAT)
            if self.f.tell() + dylib_size > cmd_start + cmdsize:
                return None
                
            dylib_data = self.f.read(dylib_size)
            if len(dylib_data) != dylib_size:
                return None
                
            (dylib_name_offset, dylib_timestamp, dylib_current_version,
            dylib_compat_version) = struct.unpack(byte_order + DYLIB_COMMAND_FORMAT, dylib_data)

            # Validate name offset
            if dylib_name_offset >= cmdsize:
                return None
            
            # Calculate available space for name
            available_space = cmdsize - dylib_name_offset
            if available_space <= 0:
                return None
                
            # Read dylib name with bounds checking
            self.f.seek(cmd_start + dylib_name_offset)
            dylib_name_data = self.f.read(min(available_space, MAX_SYMBOL_NAME_LENGTH))
            
            # Find null terminator
            null_pos = dylib_name_data.find(b'\x00')
            if null_pos != -1:
                dylib_name = dylib_name_data[:null_pos]
            else:
                dylib_name = dylib_name_data
            
            dylib_dict = {
                "dylib_name_offset": dylib_name_offset & 0xFFFFFFFF,
                "dylib_timestamp": dylib_timestamp & 0xFFFFFFFF,
                "dylib_current_version": dylib_current_version & 0xFFFFFFFF,
                "dylib_compat_version": dylib_compat_version & 0xFFFFFFFF,
                "dylib_name": dylib_name,
            }
            return dylib_dict
            
        except (struct.error, IOError):
            return None

    def _parse_dyld_info_command(self, cmd_start, byte_order):
        """Parse LC_DYLD_INFO command."""
        try:
            self.f.seek(cmd_start + 8)
            
            dyld_info_fmt = byte_order + DYLIB_INFO_FORMAT
            dyld_data = self.f.read(struct.calcsize(dyld_info_fmt))
            if len(dyld_data) != struct.calcsize(dyld_info_fmt):
                return None
                
            (rebase_off, rebase_size, bind_off, bind_size, weak_bind_off,
            weak_bind_size, lazy_bind_off, lazy_bind_size, export_off,
            export_size) = struct.unpack(dyld_info_fmt, dyld_data)
            
            return {
                'rebase_off': rebase_off,
                'rebase_size': rebase_size,
                'bind_off': bind_off,
                'bind_size': bind_size,
                'weak_bind_off': weak_bind_off,
                'weak_bind_size': weak_bind_size,
                'lazy_bind_off': lazy_bind_off,
                'lazy_bind_size': lazy_bind_size,
                'export_off': export_off,
                'export_size': export_size
            }
            
        except (struct.error, IOError):
            return None

    def _parse_export_trie_command(self, cmd_start, byte_order):
        """Parse LC_DYLD_EXPORTS_TRIE command."""
        try:
            self.f.seek(cmd_start + 8)
            
            export_trie_fmt = byte_order + EXPORT_TRIE_FORMAT
            export_data = self.f.read(struct.calcsize(export_trie_fmt))
            if len(export_data) != struct.calcsize(export_trie_fmt):
                return None
                
            data_off, data_size = struct.unpack(export_trie_fmt, export_data)
            
            return {
                'data_off': data_off,
                'data_size': data_size
            }
            
        except (struct.error, IOError):
            return None

    def _parse_uuid_command(self, cmd_start):
        """Parse LC_UUID command."""
        try:
            self.f.seek(cmd_start + 8)
            
            uuid_data = self.f.read(16)
            if len(uuid_data) != 16:
                return None
                
            # Format UUID as standard string (8-4-4-4-12 format)
            uuid_bytes = struct.unpack("16B", uuid_data)
            return "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(
                *uuid_bytes)
                
        except (struct.error, IOError):
            return None

    def _parse_main_command(self, cmd_start, byte_order):
        """Parse LC_MAIN command."""
        try:
            self.f.seek(cmd_start + 8)
            
            main_fmt = byte_order + MAIN_COMMAND_FORMAT
            main_data = self.f.read(struct.calcsize(main_fmt))
            if len(main_data) != struct.calcsize(main_fmt):
                return None
                
            entryoff, stacksize = struct.unpack(main_fmt, main_data)
            
            return {
                'type': 'LC_MAIN',
                'entryoff': entryoff & 0xFFFFFFFFFFFFFFFF,
                'stacksize': stacksize & 0xFFFFFFFFFFFFFFFF
            }
            
        except (struct.error, IOError):
            return None

    def _parse_unixthread_command(self, cmd_start, cmdsize, byte_order, is_64_bit):
        """Parse LC_UNIXTHREAD command with improved safety."""
        try:
            self.f.seek(cmd_start + 8)
            
            # Read thread command data
            thread_data_size = cmdsize - 8
            if thread_data_size <= 0:
                return None
                
            thread_data = self.f.read(min(thread_data_size, 1024))  # Limit read size
            if len(thread_data) < 8:
                return None
            
            # Parse thread state to extract entry point
            entry_address = None
            
            # Read flavor and count from thread data
            flavor, count = struct.unpack(byte_order + "II", thread_data[:8])
            
            # Get CPU type from cached header info
            try:
                header = self.get_macho_header()
                cputype = header.get('cputype', 0)
            except:
                cputype = 0
            
            # Extract entry point based on architecture with bounds checking
            if cputype == CPU_TYPE_X86_64 and len(thread_data) >= 136:
                rip_offset = 8 + 16 * 8
                if len(thread_data) >= rip_offset + 8:
                    entry_address = struct.unpack(byte_order + "Q", 
                                                thread_data[rip_offset:rip_offset + 8])[0]
            
            elif cputype == CPU_TYPE_X86 and len(thread_data) >= 48:
                eip_offset = 8 + 10 * 4
                if len(thread_data) >= eip_offset + 4:
                    entry_address = struct.unpack(byte_order + "I", 
                                                thread_data[eip_offset:eip_offset + 4])[0]
            
            elif cputype == CPU_TYPE_ARM64 and len(thread_data) >= 272:
                pc_offset = 8 + 29 * 8 + 8 + 8
                if len(thread_data) >= pc_offset + 8:
                    entry_address = struct.unpack(byte_order + "Q", 
                                                thread_data[pc_offset:pc_offset + 8])[0]
            
            return {
                'type': 'LC_UNIXTHREAD',
                'entry_address': entry_address & 0xFFFFFFFFFFFFFFFF if entry_address else None,
                'thread_data_size': thread_data_size & 0xFFFFFFFF,
            }
            
        except (struct.error, IOError):
            return None

    def _parse_version_command(self, cmd_start, cmd, byte_order):
        """Parse version command."""
        try:
            self.f.seek(cmd_start + 8)
            
            version_fmt = byte_order + VERSION_COMMAND_FORMAT
            version_data = self.f.read(struct.calcsize(version_fmt))
            if len(version_data) != struct.calcsize(version_fmt):
                return None
                
            version, sdk = struct.unpack(version_fmt, version_data)
            
            return {
                'platform_cmd': cmd & 0xFFFFFFFF,
                'min_version': version & 0xFFFFFFFF,
                'sdk_version': sdk & 0xFFFFFFFF
            }
            
        except (struct.error, IOError):
            return None

    def _parse_code_signature_command(self, cmd_start, byte_order):
        """Parse LC_CODE_SIGNATURE command."""
        try:
            self.f.seek(cmd_start + 8)
            
            code_sig_fmt = byte_order + CODE_SIGNATURE_FORMAT
            code_sig_data = self.f.read(struct.calcsize(code_sig_fmt))
            if len(code_sig_data) != struct.calcsize(code_sig_fmt):
                return None
                
            dataoff, datasize = struct.unpack(code_sig_fmt, code_sig_data)
            
            # Validate signature data bounds
            if dataoff + datasize > len(self.data):
                return None
            
            return {
                'data_off': dataoff,
                'data_size': datasize
            }
            
        except (struct.error, IOError):
            return None

    def parse_code_signature(self):
        """Parse code signature with enhanced error handling."""
        if not hasattr(self, 'code_signature_data') or not self.code_signature_data:
            return self._empty_signature_result()
        
        try:
            # Validate signature data bounds
            data_off = self.code_signature_data['data_off']
            data_size = self.code_signature_data['data_size']
            
            if data_off + data_size > len(self.data):
                return self._empty_signature_result()
            
            # Read the code signature data
            self.f.seek(data_off)
            signature_data = self.f.read(data_size)
            
            if len(signature_data) < 12:  # Minimum superblob size
                return self._empty_signature_result()
            
            # Parse the superblob header
            magic, length, count = struct.unpack(">III", signature_data[:12])
            
            if magic != CSMAGIC_EMBEDDED_SIGNATURE:
                return self._empty_signature_result()
            
            # Validate superblob structure
            if length > len(signature_data) or count > 100:  # Reasonable upper limit
                return self._empty_signature_result()
            
            # Parse blob index entries with bounds checking
            blobs = []
            offset = 12
            for i in range(min(count, 100)):  # Limit iterations
                if offset + 8 > len(signature_data):
                    break
                blob_type, blob_offset = struct.unpack(">II", signature_data[offset:offset + 8])
                if blob_offset < len(signature_data):  # Validate offset
                    blobs.append({'type': blob_type, 'offset': blob_offset})
                offset += 8
            
            # Extract information from blobs
            certificates = {'count': 0, 'certificates': []}
            entitlements = {'count': 0, 'entitlements': {}}
            code_directory = None
            cert_index = 0
            
            for blob in blobs:
                blob_offset = blob['offset']
                blob_type = blob['type']
                
                if blob_offset + 8 > len(signature_data):
                    continue
                    
                # Parse blob header
                try:
                    blob_magic, blob_length = struct.unpack(">II", 
                                                            signature_data[blob_offset:blob_offset + 8])
                    
                    # Validate blob length
                    if blob_length > len(signature_data) - blob_offset or blob_length < 8:
                        continue
                    
                    # Process different blob types
                    if blob_type >= CSSLOT_SIGNATURESLOT:
                        # Certificate blob
                        if blob_magic == CSMAGIC_BLOBWRAPPER:
                            cert_list = self._parse_certificate_blob(signature_data, blob_offset, blob_length, cert_index)
                            if cert_list:
                                certificates['certificates'].extend(cert_list)
                                cert_index += len(cert_list)
                    
                    elif blob_type == CSSLOT_ENTITLEMENTS and blob_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
                        entitlements = self._parse_entitlements_blob(signature_data, blob_offset, blob_length)
                    
                    elif blob_type == CSSLOT_DER_ENTITLEMENTS and blob_magic == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
                        if entitlements['count'] == 0:
                            entitlements = self._parse_der_entitlements_blob(signature_data, blob_offset, blob_length)
                    
                    elif blob_type == CSSLOT_CODEDIRECTORY and blob_magic == CSMAGIC_CODEDIRECTORY:
                        code_directory = self._parse_code_directory_blob(signature_data, blob_offset, blob_length)
                
                except (struct.error, IndexError):
                    continue
            
            # Update certificate count
            certificates['count'] = len(certificates['certificates'])
            
            # Determine signing status
            signing_status = self._determine_signing_status(certificates, code_directory)
            
            return {
                'signed': certificates['count'] > 0 or code_directory is not None,
                'signing_status': signing_status,
                'certificates_info': certificates,
                'entitlements_info': entitlements,
                'code_directory': code_directory
            }
            
        except (struct.error, IOError, MemoryError) as e:
            return self._empty_signature_result()

    def _empty_signature_result(self):
        """Return empty signature result structure."""
        return {
            'signed': False,
            'signing_status': 'Unsigned',
            'certificates_info': {'count': 0, 'certificates': []},
            'entitlements_info': {'count': 0, 'entitlements': {}},
            'code_directory': None
        }

    def _parse_entitlements_blob(self, signature_data, offset, length):
        """Parse entitlements from embedded entitlements blob with better error handling."""
        entitlements = {}
        
        try:
            # Skip blob header (8 bytes) to get to XML data
            xml_start = offset + 8
            xml_end = offset + length
            
            if xml_end > len(signature_data) or xml_start >= xml_end:
                return {'count': 0, 'entitlements': {}}
                
            xml_data = signature_data[xml_start:xml_end]
            
            # Limit XML data size for security
            if len(xml_data) > 1024 * 1024:  # 1MB limit
                xml_data = xml_data[:1024 * 1024]
            
            try:
                xml_string = xml_data.decode('utf-8', errors='ignore')
            except (UnicodeDecodeError, MemoryError):
                return {'count': 0, 'entitlements': {}}
            
            # Simple XML parsing for entitlements
            import re
            
            # Find boolean entitlements
            bool_pattern = r'<key>([^<]+)</key>\s*<(true|false)/>'
            bool_matches = re.findall(bool_pattern, xml_string, re.IGNORECASE)
            
            for key, value_type in bool_matches:
                if len(key) <= MAX_SYMBOL_NAME_LENGTH:  # Limit key length
                    entitlements[key.strip()] = {
                        'type': 'boolean',
                        'value': True if value_type.lower() == 'true' else False
                    }
            
            # Find string entitlements
            string_pattern = r'<key>([^<]+)</key>\s*<string>([^<]*)</string>'
            string_matches = re.findall(string_pattern, xml_string, re.IGNORECASE)
            
            for key, value in string_matches:
                if len(key) <= MAX_SYMBOL_NAME_LENGTH and len(value) <= MAX_SYMBOL_NAME_LENGTH:
                    entitlements[key.strip()] = {
                        'type': 'string',
                        'value': value.strip()
                    }
            
            # Find array entitlements
            array_pattern = r'<key>([^<]+)</key>\s*<array>(.*?)</array>'
            array_matches = re.findall(array_pattern, xml_string, re.DOTALL | re.IGNORECASE)
            
            for key, array_content in array_matches:
                if len(key) <= MAX_SYMBOL_NAME_LENGTH:
                    # Extract string values from array
                    string_pattern = r'<string>([^<]+)</string>'
                    string_values = re.findall(string_pattern, array_content)
                    
                    # Limit array size and element length
                    filtered_values = []
                    for val in string_values[:100]:  # Max 100 array elements
                        if len(val) <= MAX_SYMBOL_NAME_LENGTH:
                            filtered_values.append(val)
                    
                    entitlements[key.strip()] = {
                        'type': 'array',
                        'value': filtered_values
                    }
            
            return {
                'count': len(entitlements),
                'entitlements': entitlements
            }
                    
        except (UnicodeDecodeError, AttributeError, MemoryError, re.error):
            return {'count': 0, 'entitlements': {}}

    def _parse_der_entitlements_blob(self, signature_data, offset, length):
        """Parse DER encoded entitlements with enhanced safety."""
        try:
            # Skip blob header (8 bytes) to get to DER data
            der_start = offset + 8
            der_end = offset + length
            
            if der_end > len(signature_data) or der_start >= der_end:
                return {'count': 0, 'entitlements': {}, 'format': 'DER'}
                
            der_data = signature_data[der_start:der_end]
            
            # Limit DER data size for security
            if len(der_data) > 1024 * 1024:  # 1MB limit
                der_data = der_data[:1024 * 1024]
            
            entitlements = {}
            
            # Convert to string and look for common entitlement patterns
            try:
                der_string = der_data.decode('utf-8', errors='ignore')
            except (UnicodeDecodeError, MemoryError):
                return {'count': 0, 'entitlements': {}, 'format': 'DER'}
            
            # Common entitlement key patterns to look for
            entitlement_patterns = [
                'com.apple.developer.',
                'com.apple.security.',
                'application-identifier',
                'team-identifier',
                'get-task-allow',
                'platform-application',
                'com.apple.private.',
                'keychain-access-groups'
            ]
            
            for pattern in entitlement_patterns:
                if pattern in der_string:
                    entitlements[pattern] = {
                        'type': 'detected',
                        'value': 'Present (DER encoded)'
                    }
            
            return {
                'count': len(entitlements),
                'entitlements': entitlements,
                'format': 'DER',
                'note': 'DER entitlements detected but not fully parsed'
            }
                    
        except (UnicodeDecodeError, AttributeError, MemoryError):
            return {'count': 0, 'entitlements': {}, 'format': 'DER'}

    def _parse_certificate_blob(self, signature_data, offset, length, cert_index=0):
        """Parse certificate information from blobwrapper with enhanced validation."""
        certificates = []
        
        try:
            # Skip blob header (8 bytes) to get to certificate data
            cert_start = offset + 8
            cert_end = offset + length
            
            if cert_end > len(signature_data) or cert_start >= cert_end:
                return certificates
                
            cert_data = signature_data[cert_start:cert_end]
            
            # Limit certificate data size
            if len(cert_data) > 10 * 1024 * 1024:  # 10MB limit
                return certificates
            
            # Parse multiple DER-encoded certificates
            position = 0
            current_cert_index = cert_index
            max_certs = 10  # Reasonable limit
            
            while position < len(cert_data) and len(certificates) < max_certs:
                if position + 4 >= len(cert_data):
                    break
                    
                if cert_data[position] == 0x30:
                    # Parse DER length encoding
                    cert_length = self._parse_der_length(cert_data, position)
                    if cert_length is None or cert_length < 100 or cert_length > len(cert_data) - position:
                        position += 1
                        continue
                    
                    # Extract certificate
                    if position + cert_length <= len(cert_data):
                        single_cert_data = cert_data[position:position + cert_length]
                        
                        if self._looks_like_certificate(single_cert_data):
                            cert_info = self._parse_single_certificate(single_cert_data, current_cert_index)
                            if cert_info and cert_info['size'] >= 500:  # Minimum reasonable size
                                certificates.append(cert_info)
                                current_cert_index += 1
                        
                        position += cert_length
                    else:
                        break
                else:
                    position += 1
            
            return certificates
            
        except (struct.error, IndexError, MemoryError):
            return certificates

    def _parse_der_length(self, data, position):
        """Parse DER length encoding safely."""
        try:
            if position + 1 >= len(data):
                return None
                
            if data[position + 1] == 0x82:
                # Long form length (2 bytes)
                if position + 4 >= len(data):
                    return None
                return struct.unpack(">H", data[position + 2:position + 4])[0] + 4
            elif data[position + 1] == 0x81:
                # Medium form length (1 byte)
                if position + 3 >= len(data):
                    return None
                return data[position + 2] + 3
            elif data[position + 1] & 0x80 == 0:
                # Short form length
                return data[position + 1] + 2
            else:
                return None
        except (struct.error, IndexError):
            return None

    def _looks_like_certificate(self, cert_data):
        """Check if the data looks like a valid X.509 certificate with improved validation."""
        try:
            if len(cert_data) < 100:
                return False
            
            # Should start with SEQUENCE tag (0x30)
            if cert_data[0] != 0x30:
                return False
            
            # Convert to string for pattern matching
            try:
                cert_string = cert_data.decode('utf-8', errors='ignore')
            except (UnicodeDecodeError, MemoryError):
                return False
            
            # X.509 certificates typically contain these patterns
            certificate_indicators = [
                '1.2.840.113549',  # RSA OID
                '1.2.840.10045',   # ECDSA OID  
                '2.5.4.',          # Attribute OID prefix
                'Apple',
                'Developer',
                'CA'
            ]
            
            found_indicators = sum(1 for indicator in certificate_indicators if indicator in cert_string)
            
            # Require at least 2 indicators
            return found_indicators >= 2
            
        except (UnicodeDecodeError, IndexError, MemoryError):
            return False

    def _parse_single_certificate(self, cert_data, cert_index):
        """Parse a single DER-encoded X.509 certificate with improved safety."""
        try:
            cert_info = {
                'index': cert_index,
                'size': len(cert_data),
                'subject': 'Unable to parse',
                'issuer': 'Unable to parse',
                'is_apple_cert': False,
                'type': 'Unknown'
            }
            
            # Look for certificate patterns in the raw data
            try:
                cert_string = cert_data.decode('utf-8', errors='ignore')
            except (UnicodeDecodeError, MemoryError):
                return cert_info
            
            # Certificate type detection patterns (order matters!)
            cert_patterns = [
                ('Developer ID Application:', 'Developer ID Application Certificate', False),
                ('Developer ID Certification Authority', 'Developer ID Certification Authority', True),
                ('Apple Root CA', 'Apple Root CA', True),
                ('Apple Worldwide Developer Relations Certification Authority', 'Apple WWDR CA', True),
                ('Mac App Store', 'Mac App Store Certificate', True),
                ('Apple Development', 'Apple Development Certificate', True),
                ('Apple Distribution', 'Apple Distribution Certificate', True),
            ]
            
            # Check for specific certificate patterns
            for pattern, cert_type, is_apple in cert_patterns:
                if pattern in cert_string:
                    cert_info['is_apple_cert'] = is_apple
                    cert_info['type'] = cert_type
                    if cert_info['subject'] == 'Unable to parse':
                        cert_info['subject'] = f"Contains: {pattern}"
                    break
            else:
                # Fallback: if it contains "Apple Inc." but didn't match specific patterns, it's likely an Apple cert
                if 'Apple Inc.' in cert_string:
                    cert_info['is_apple_cert'] = True
                    cert_info['type'] = 'Apple Certificate'
                    if cert_info['subject'] == 'Unable to parse':
                        cert_info['subject'] = "Contains: Apple Inc."
            
            return cert_info
            
        except (UnicodeDecodeError, struct.error):
            return None

    def _parse_code_directory_blob(self, signature_data, offset, length):
        """Parse code directory information with enhanced parsing for newer versions."""
        try:
            # Skip blob header (8 bytes) and parse code directory structure
            cd_start = offset + 8
            
            if cd_start + 20 > len(signature_data):
                return None
                
            # Parse basic code directory fields
            cd_data = signature_data[cd_start:cd_start + 20]
            version, flags, hash_offset, ident_offset, n_special_slots = struct.unpack(">IIIII", cd_data)
            
            code_directory = {
                'version': version,
                'flags': flags,
                'hash_offset': hash_offset,
                'identifier_offset': ident_offset,
                'special_slots': n_special_slots,
                'signing_flags': self._decode_signing_flags(flags)
            }
            
            # Parse additional fields based on version and available data
            current_offset = cd_start + 20
            
            # Parse hash algorithm and other fields if we have enough data
            if current_offset + 12 <= cd_start + length:
                n_code_slots, hash_size, hash_type = struct.unpack(">III", 
                                                                  signature_data[current_offset:current_offset + 12])
                code_directory.update({
                    'code_slots': n_code_slots,
                    'hash_size': hash_size, 
                    'hash_type': hash_type,
                    'hash_algorithm': self._decode_hash_algorithm(hash_type)
                })
                current_offset += 12
                
                # Parse spare fields (version >= 20100)
                if version >= 20100 and current_offset + 12 <= cd_start + length:
                    spare1, spare2, spare3 = struct.unpack(">III", 
                                                           signature_data[current_offset:current_offset + 12])
                    current_offset += 12
                    
                    # Parse Team ID (version >= 20200)
                    if version >= 20200 and current_offset + 4 <= cd_start + length:
                        team_offset = struct.unpack(">I", signature_data[current_offset:current_offset + 4])[0]
                        current_offset += 4
                        
                        if team_offset > 0 and cd_start + team_offset < len(signature_data):
                            team_start = cd_start + team_offset
                            team_end = signature_data.find(b'\x00', team_start)
                            if team_end > team_start:
                                team_id = signature_data[team_start:team_end].decode('utf-8', errors='ignore')
                                code_directory['team_id'] = team_id
            
            # Try to extract identifier string if possible
            if ident_offset > 0 and cd_start + ident_offset < len(signature_data):
                # Find null-terminated string at identifier offset
                ident_start = cd_start + ident_offset
                ident_end = signature_data.find(b'\x00', ident_start)
                if ident_end > ident_start:
                    identifier = signature_data[ident_start:ident_end].decode('utf-8', errors='ignore')
                    code_directory['identifier'] = identifier
            
            return code_directory
            
        except (struct.error, UnicodeDecodeError):
            return None

    def _decode_signing_flags(self, flags):
        """Decode code signing flags to human-readable format."""
        flag_meanings = {
            0x1: 'Host',
            0x2: 'Adhoc',
            0x4: 'ForceHard',
            0x8: 'Kill',
            0x10: 'Hard',
            0x20: 'Runtime',
            0x40: 'LinkerSigned',
            0x100: 'AllowUnsignedExecutables',
            0x200: 'DebuggingAllowed',
            0x400: 'JustMyCode',
            0x800: 'Restrict',
            0x1000: 'Enforcement',
            0x2000: 'LibraryValidation'
        }
        
        active_flags = []
        for flag_value, flag_name in flag_meanings.items():
            if flags & flag_value:
                active_flags.append(flag_name)
        
        return active_flags if active_flags else ['None']

    def _decode_hash_algorithm(self, hash_type):
        """Decode hash algorithm type to human-readable format."""
        hash_algorithms = {
            CS_HASHTYPE_SHA1: 'SHA-1',
            CS_HASHTYPE_SHA256: 'SHA-256',
            CS_HASHTYPE_SHA256_TRUNCATED: 'SHA-256 (truncated)',
            CS_HASHTYPE_SHA384: 'SHA-384'
        }
        
        return hash_algorithms.get(hash_type, f'Unknown ({hash_type})')

    def _determine_signing_status(self, certificates, code_directory):
        """Determine the overall signing status of the binary."""
        if not certificates['count'] and not code_directory:
            return 'Unsigned'
        
        if code_directory:
            flags = code_directory.get('signing_flags', [])
            if 'Adhoc' in flags:
                return 'Ad-hoc signed'
            elif 'Runtime' in flags:
                return 'Signed with runtime hardening'
            elif certificates['count'] > 0:
                # Check if it's an Apple certificate
                apple_cert = any(cert.get('is_apple_cert', False) for cert in certificates['certificates'])
                if apple_cert:
                    return 'Apple signed'
                else:
                    return 'Developer signed'
        
        if certificates['count'] > 0:
            return 'Signed (certificate present)'
        
        return 'Signed (code directory only)'

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
        """Extract exports using export trie with default filtering"""
        exports = {}
        
        # Try export trie first (modern samples)
        if self.has_export_trie():
            exports = self.parse_export_trie()
        else:
            # For old samples, fallback to existing symbol table method
            exports = self.get_exported_symbols_oldway() 
        
        return exports


    def parse_export_trie(self):
        """Parse export trie from LC_DYLD_INFO or LC_DYLD_EXPORTS_TRIE.
        
        Returns:
            dict: Dictionary mapping dylib name to list of exported symbol names from the export trie.
        """
        exports = []
        
        # Check for export trie data sources
        export_data_sources = []
        
        # Get export data from LC_DYLD_INFO if available
        if hasattr(self, 'dyld_info') and self.dyld_info:
            export_off = self.dyld_info.get('export_off', 0)
            export_size = self.dyld_info.get('export_size', 0)
            if export_off > 0 and export_size > 0:
                export_data_sources.append((export_off, export_size))
        
        # Get export data from LC_DYLD_EXPORTS_TRIE if available  
        if hasattr(self, 'dyld_export_trie') and self.dyld_export_trie:
            data_off = self.dyld_export_trie.get('data_off', 0)
            data_size = self.dyld_export_trie.get('data_size', 0)
            if data_off > 0 and data_size > 0:
                export_data_sources.append((data_off, data_size))
        
        # Process each export data source
        for offset, size in export_data_sources:
            try:
                self.f.seek(offset)
                export_data = self.f.read(size)
                if len(export_data) == size:
                    trie_exports = self._parse_export_trie_data(export_data)
                    exports.extend(trie_exports)
            except (IOError, struct.error):
                # Continue with other sources if one fails
                continue
        
        # Remove duplicates
        seen = set()
        unique_exports = []
        for export in exports:
            if export not in seen:
                seen.add(export)
                unique_exports.append(export)
        
        # Return as dictionary with single key for all exports (since export trie doesn't have dylib info)
        if unique_exports:
            return {"<export_trie>": unique_exports}
        else:
            return {}

    def _parse_export_trie_data(self, data):
        """Parse the actual export trie data structure.
        
        Args:
            data: Raw export trie data bytes.
            
        Returns:
            list: List of exported symbol names.
        """
        exports = []
        if not data:
            return exports
        
        # Stack for traversing the trie: (offset, prefix)
        stack = [(0, "")]
        visited = set()
        
        while stack:
            offset, prefix = stack.pop()
            
            # Prevent infinite loops on malformed data
            if offset in visited or offset >= len(data):
                continue
            visited.add(offset)
            
            try:
                # Read terminal size (ULEB128)
                terminal_size, consumed = self._read_uleb128(data, offset)
                current_offset = offset + consumed
                
                # If terminal size > 0, this node exports a symbol
                if terminal_size > 0:
                    # Skip the export info (flags, offset, etc.)
                    # We only need the symbol name (prefix)
                    if prefix:  # Don't add empty names
                        # check if export symbol is __mh_execute_header and skip default export
                        if prefix == "__mh_execute_header":
                            # Check if this is the default export at offset 0
                            file_offset = self._get_symbol_file_offset(prefix)
                            if file_offset == 0:
                                # Skip default export
                                current_offset += terminal_size
                                continue

                        exports.append(prefix)
                    
                    # Skip over the terminal data
                    current_offset += terminal_size
                
                # Read number of child edges
                if current_offset >= len(data):
                    continue
                    
                num_edges = data[current_offset]
                current_offset += 1
                
                # Process each child edge
                for _ in range(num_edges):
                    if current_offset >= len(data):
                        break
                    
                    # Read edge label (null-terminated string)
                    label_start = current_offset
                    while current_offset < len(data) and data[current_offset] != 0:
                        current_offset += 1
                    
                    if current_offset >= len(data):
                        break
                        
                    # Extract label
                    label = data[label_start:current_offset].decode('utf-8', errors='replace')
                    current_offset += 1  # Skip null terminator
                    
                    # Read child node offset (ULEB128)
                    if current_offset >= len(data):
                        break
                        
                    child_offset, consumed = self._read_uleb128(data, current_offset)
                    current_offset += consumed
                    
                    # Add child to stack with concatenated prefix
                    new_prefix = prefix + label
                    stack.append((child_offset, new_prefix))
                    
            except (IndexError, UnicodeDecodeError, struct.error):
                # Skip malformed nodes
                continue
        
        return exports

    def _get_symbol_file_offset(self, symbol_name):
        """Get the file offset for a given symbol name by looking it up in the symbol table.
        
        Args:
            symbol_name: Name of the symbol to find.
            
        Returns:
            int: File offset of the symbol, or None if not found.
        """
        self.f.seek(0)
        magic = struct.unpack("I", self.f.read(4))[0]
        is_64_bit = True if magic in {MH_MAGIC_64, MH_CIGAM_64} else False
        byte_order = ">" if magic in {MH_CIGAM, MH_CIGAM_64} else "<"

        # Skip to load commands
        self.f.seek(12, 1)
        ncmds = struct.unpack("I", self.f.read(4))[0]
        if is_64_bit:
            self.f.seek(12, 1)
        else:
            self.f.seek(8, 1)

        # Find LC_SYMTAB
        symtab = None
        for _ in range(ncmds):
            cmd_start = self.f.tell()
            cmd, cmdsize = struct.unpack(byte_order + LOAD_COMMAND_FORMAT, self.f.read(8))
            rest_of_cmd = self.f.read(cmdsize - 8)
            full_cmd = struct.pack(byte_order + LOAD_COMMAND_FORMAT, cmd, cmdsize) + rest_of_cmd
            if cmd == LOAD_COMMAND_TYPES["LC_SYMTAB"]:
                symtab = struct.unpack(byte_order + SYMTAB_COMMAND_FORMAT, 
                                    full_cmd[:struct.calcsize(byte_order + SYMTAB_COMMAND_FORMAT)])
                break
            self.f.seek(cmd_start + cmdsize)

        if not symtab:
            return None

        # Parse symbol table to find the symbol
        symoff = symtab[2]
        nsyms = symtab[3]
        stroff = symtab[4]
        strsize = symtab[5]

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

        # Search for the symbol
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

            # Get symbol name
            str_offset = n_strx
            if str_offset < len(string_table):
                name = string_table[str_offset:string_table.find(b"\x00", str_offset)]
                if not name:
                    continue
                current_symbol_name = name.decode(errors="replace")
                
                # Check if this is the symbol we're looking for
                if current_symbol_name == symbol_name:
                    # Only process defined external symbols (N_SECT and N_EXT)
                    if (n_type & N_TYPE) == N_SECT and (n_type & N_EXT):
                        # Calculate file offset from virtual address using segment mapping
                        file_offset = None
                        for segment in self.segments:
                            if (n_value >= segment["vaddr"] and 
                                n_value < segment["vaddr"] + segment["vsize"]):
                                # Calculate offset within the segment
                                offset_in_segment = n_value - segment["vaddr"]
                                file_offset = segment["offset"] + offset_in_segment
                                break
                        
                        return file_offset
        
        return None

    def _read_uleb128(self, data, offset):
        """Read a ULEB128 encoded integer from data at offset.
        
        Args:
            data: Byte data to read from.
            offset: Starting offset in data.
            
        Returns:
            tuple: (value, bytes_consumed)
        """
        value = 0
        shift = 0
        consumed = 0
        
        while offset + consumed < len(data):
            byte = data[offset + consumed]
            consumed += 1
            
            value |= (byte & 0x7F) << shift
            
            # Check if this is the last byte (MSB is 0)
            if (byte & 0x80) == 0:
                break
                
            shift += 7
            
            # Prevent infinite loops on malformed data
            if shift >= 64:
                break
        
        return value, consumed

    def has_export_trie(self):
        """Check if this Mach-O file has export trie data.
        
        Returns:
            bool: True if export trie data is available.
        """
        # Check LC_DYLD_INFO export data
        if hasattr(self, 'dyld_info') and self.dyld_info:
            export_size = self.dyld_info.get('export_size', 0)
            if export_size > 0:
                return True
        
        # Check LC_DYLD_EXPORTS_TRIE
        if hasattr(self, 'dyld_export_trie') and self.dyld_export_trie:
            data_size = self.dyld_export_trie.get('data_size', 0)
            if data_size > 0:
                return True
        
        return False


    def get_exported_symbols_oldway(self):
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

# --- JSON Helper Functions ---
def make_json_serializable(data):
    """Convert data structures to be JSON serializable."""
    if isinstance(data, dict):
        return {k: make_json_serializable(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [make_json_serializable(item) for item in data]
    elif isinstance(data, set):
        return sorted(list(data))
    elif isinstance(data, bytes):
        try:
            # Try to decode as UTF-8 first
            return data.decode('utf-8')
        except UnicodeDecodeError:
            # If that fails, use repr() to show bytes representation
            return repr(data)
    elif isinstance(data, (int, float, str, bool, type(None))):
        return data
    else:
        # For other types, convert to string representation
        return str(data)

def collect_all_data(macho, args, target_arch=None, raw=True):
    """Collect all requested data into a dictionary structure for JSON output."""
    data = {}
    
    def get_arch_data(attr_name):
        """Get attribute data for target architecture or all architectures."""
        if target_arch:
            macho_instance = macho.get_macho_for_arch(target_arch)
            return getattr(macho_instance, attr_name, None) if macho_instance else None
        else:
            return getattr(macho, attr_name, None)
    
    # General info
    if args.all or args.general_info:
        data['general_info'] = macho.get_general_info(target_arch)
    
    # Header
    if args.all or args.header:
        raw_header = macho.get_macho_header(target_arch)
        if raw and raw_header is not None:
            data['header'] = raw_header
        elif raw_header is not None:
            # Apply formatting
            if isinstance(raw_header, dict) and 'magic' in raw_header:
                # Single architecture case
                if target_arch:
                    macho_instance = macho.get_macho_for_arch(target_arch)
                else:
                    macho_instance = macho.macho if hasattr(macho, 'macho') else list(macho.architectures.values())[0] if macho.is_fat else macho
                if macho_instance:
                    data['header'] = macho_instance.format_header_for_display(raw_header)
                else:
                    data['header'] = raw_header
            elif isinstance(raw_header, dict):
                # Multi-architecture case
                formatted_data = {}
                for arch_name, arch_header in raw_header.items():
                    if isinstance(arch_header, dict) and 'magic' in arch_header:
                        macho_instance = macho.get_macho_for_arch(arch_name)
                        if macho_instance:
                            formatted_data[arch_name] = macho_instance.format_header_for_display(arch_header)
                        else:
                            formatted_data[arch_name] = arch_header
                    else:
                        formatted_data[arch_name] = arch_header
                data['header'] = formatted_data
            else:
                data['header'] = raw_header
    
    # Load commands
    if args.all or args.load_cmd_t:
        raw_load_commands = get_arch_data('load_commands')
        if raw or raw_load_commands is None:
            data['load_commands'] = raw_load_commands
        else:
            # Apply formatting
            if isinstance(raw_load_commands, list) and raw_load_commands:
                # Single architecture case
                if target_arch:
                    macho_instance = macho.get_macho_for_arch(target_arch)
                else:
                    macho_instance = macho.macho if hasattr(macho, 'macho') else list(macho.architectures.values())[0] if macho.is_fat else macho
                if macho_instance:
                    data['load_commands'] = macho_instance.format_load_commands_for_display(raw_load_commands)
                else:
                    data['load_commands'] = raw_load_commands
            elif isinstance(raw_load_commands, dict):
                # Multi-architecture case
                formatted_data = {}
                for arch_name, arch_load_commands in raw_load_commands.items():
                    if isinstance(arch_load_commands, list):
                        macho_instance = macho.get_macho_for_arch(arch_name)
                        if macho_instance:
                            formatted_data[arch_name] = macho_instance.format_load_commands_for_display(arch_load_commands)
                        else:
                            formatted_data[arch_name] = arch_load_commands
                    else:
                        formatted_data[arch_name] = arch_load_commands
                data['load_commands'] = formatted_data
            else:
                data['load_commands'] = raw_load_commands
        
        # Load commands set
        raw_load_commands_set = get_arch_data('load_commands_set')
        if raw or raw_load_commands_set is None:
            data['load_commands_set'] = raw_load_commands_set
        else:
            # Apply formatting
            if isinstance(raw_load_commands_set, set) and raw_load_commands_set:
                # Single architecture case
                if target_arch:
                    macho_instance = macho.get_macho_for_arch(target_arch)
                else:
                    macho_instance = macho.macho if hasattr(macho, 'macho') else list(macho.architectures.values())[0] if macho.is_fat else macho
                if macho_instance:
                    data['load_commands_set'] = sorted([macho_instance.format_load_command(cmd) for cmd in raw_load_commands_set])
                else:
                    data['load_commands_set'] = sorted(list(raw_load_commands_set))
            elif isinstance(raw_load_commands_set, dict):
                # Multi-architecture case
                formatted_data = {}
                for arch_name, arch_set in raw_load_commands_set.items():
                    if isinstance(arch_set, set):
                        macho_instance = macho.get_macho_for_arch(arch_name)
                        if macho_instance:
                            formatted_data[arch_name] = sorted([macho_instance.format_load_command(cmd) for cmd in arch_set])
                        else:
                            formatted_data[arch_name] = sorted(list(arch_set))
                    else:
                        formatted_data[arch_name] = arch_set
                data['load_commands_set'] = formatted_data
            else:
                data['load_commands_set'] = raw_load_commands_set
    
    # Segments
    if args.all or args.segments:
        data['segments'] = get_arch_data('segments')
    
    # Dylib info
    if args.all or args.dylib:
        data['dylib_commands'] = get_arch_data('dylib_commands')
        data['dylib_names'] = get_arch_data('dylib_names')
    
    # UUID
    if args.all or args.uuid:
        data['uuid'] = get_arch_data('uuid')
    
    # Entry point
    if args.all or args.entry_point:
        data['entry_point'] = get_arch_data('entry_point')
    
    # Version info
    if args.all or args.version:
        raw_version_info = get_arch_data('version_info')
        if raw or raw_version_info is None:
            data['version_info'] = raw_version_info
        else:
            # Apply formatting
            if isinstance(raw_version_info, dict) and 'platform_cmd' in raw_version_info:
                # Single architecture case
                if target_arch:
                    macho_instance = macho.get_macho_for_arch(target_arch)
                else:
                    macho_instance = macho.macho if hasattr(macho, 'macho') else list(macho.architectures.values())[0] if macho.is_fat else macho
                if macho_instance:
                    data['version_info'] = macho_instance.format_version_info_for_display(raw_version_info)
                else:
                    data['version_info'] = raw_version_info
            elif isinstance(raw_version_info, dict):
                # Multi-architecture case
                formatted_data = {}
                for arch_name, arch_version_info in raw_version_info.items():
                    if isinstance(arch_version_info, dict) and 'platform_cmd' in arch_version_info:
                        macho_instance = macho.get_macho_for_arch(arch_name)
                        if macho_instance:
                            formatted_data[arch_name] = macho_instance.format_version_info_for_display(arch_version_info)
                        else:
                            formatted_data[arch_name] = arch_version_info
                    else:
                        formatted_data[arch_name] = arch_version_info
                data['version_info'] = formatted_data
            else:
                data['version_info'] = raw_version_info
    
    # Code signature
    if args.all or args.signature:
        data['code_signature_info'] = get_arch_data('code_signature_info')
    
    # Imports
    if args.all or args.imports:
        data['imported_functions'] = macho.get_imported_functions(target_arch)
    
    # Exports  
    if args.all or args.exports:
        data['exported_symbols'] = macho.get_exported_symbols(target_arch)
    
    # Similarity hashes
    if args.all or args.similarity:
        data['similarity_hashes'] = macho.get_similarity_hashes(target_arch)
    
    # Add architecture info for context
    if macho.is_fat:
        data['architectures'] = macho.get_architectures()
        if target_arch:
            data['target_architecture'] = target_arch
    
    return data

# --- CLI Helper Functions ---
import argparse

def print_dict(d, indent_level=1):
    """Print dictionary with proper handling of nested structures."""
    if indent_level == 1:
        indent = "\t"
    else:
        indlev = "  " * indent_level
        indent = f"\t{indlev}"
    
    for k, v in d.items():
        if isinstance(v, dict):
            print(f"{indent}{k}:")
            print_dict(v, indent_level + 1)
        elif isinstance(v, list):
            print(f"{indent}{k}:")
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    if i > 0:  # Add blank line before items after the first
                        print()
                    print_dict(item, indent_level + 1)
                else:
                    print(f"{indent}\t{item}")
        else:
            if v is not None:
                print(f"{indent}{k + ':':<13}{v}")

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
    
    # Required arguments
    required = parser.add_argument_group('required arguments')
    required.add_argument(
        "-f", "--file", type=str, help="Path to the file to be parsed", required=True
    )
    
    # Output format options
    output_group = parser.add_argument_group('output format options')
    output_group.add_argument(
        "-j", "--json", action="store_true", help="Output data in JSON format"
    )
    output_group.add_argument(
        "--raw", action="store_true", help="Output raw values in JSON format (use with -j/--json)"
    )
    
    # Data extraction options (alphabetical)
    data_group = parser.add_argument_group('data extraction options')
    data_group.add_argument(
        "-a", "--all", action="store_true", help="Print all info about the file"
    )
    data_group.add_argument(
        "-d",
        "--dylib",
        action="store_true",
        help="Print Dylib Command Table and Dylib list",
    )
    data_group.add_argument(
        "-e", "--exports", action="store_true", help="Print exported symbols"
    )
    data_group.add_argument(
        "-ep", "--entry-point", dest="entry_point", action="store_true", help="Print entry point information"
    )
    data_group.add_argument(
        "-g", "--general_info", action="store_true", help="Print general info about the file"
    )
    data_group.add_argument(
        "-hdr", "--header", action="store_true", help="Print Mach-O header info"
    )
    data_group.add_argument(
        "-i", "--imports", action="store_true", help="Print imported symbols"
    )
    data_group.add_argument(
        "-l",
        "--load_cmd_t",
        action="store_true",
        help="Print Load Command Table and Command list",
    )
    data_group.add_argument(
        "-seg", "--segments", action="store_true", help="Print File Segments info"
    )
    data_group.add_argument(
        "-sig", "--signature", action="store_true", 
        help="Print code signature and entitlements information"
    )
    data_group.add_argument(
        "-sim", "--similarity", action="store_true", help="Print similarity hashes"
    )
    data_group.add_argument(
        "-u", "--uuid", action="store_true", help="Print UUID"
    )
    data_group.add_argument(
        "-v", "--version", action="store_true", help="Print version information"
    )
    
    # Filter options
    filter_group = parser.add_argument_group('filter options')
    filter_group.add_argument(
        "--arch", type=str, help="Show info for specific architecture only (for Universal binaries)"
    )

    args = parser.parse_args()
    file_path = args.file

    # Validate --raw flag usage
    if args.raw and not args.json:
        parser.error("--raw can only be used with -j/--json")

    macho = UniversalMachO(file_path=file_path)
    macho.parse()
    
    # Handle architecture selection
    target_arch = args.arch
    available_archs = macho.get_architectures()
    
    if target_arch and target_arch not in available_archs:
        print(f"Error: Architecture '{target_arch}' not found in binary.")
        print(f"Available architectures: {', '.join(available_archs)}")
        return
    
    # Handle JSON output mode
    if args.json:
        # Collect data (formatted by default, raw if --raw flag is used)
        data = collect_all_data(macho, args, target_arch, raw=args.raw)
        
        # Make data JSON serializable and output
        json_data = make_json_serializable(data)
        print(json.dumps(json_data, indent=2))
        return
    
    # Show architectures info if FAT binary and no specific arch requested
    if macho.is_fat and not target_arch:
        print(f"\n[Universal Binary - Architectures: {', '.join(available_archs)}]")

    def print_section_for_arch(section_name, data_getter, *args_check):
        """Print a section for specific arch or all archs."""
        if not any(args_check):
            return
        
        data = data_getter(target_arch)
        
        def print_data(data):
            """Print data based on its type - generic for all data structures."""
            if isinstance(data, dict):
                print_dict(data)
            elif isinstance(data, list):
                print_list(data)
            else:
                print(f"\t{data}")

        if target_arch:
            # Single architecture output
            print(f"\n[{section_name} - {target_arch}]")
            if data:
                print_data(data)
            else:
                print(f"\tNo {section_name.lower()} found")
        else:
            # Multi-architecture output
            if macho.is_fat:
                if isinstance(data, dict):
                    for arch, arch_data in data.items():
                        print(f"\n[{section_name} - {arch}]")
                        if arch_data:
                            print_data(arch_data)
                        else:
                            print(f"\tNo {section_name.lower()} found")
                else:
                    print(f"\n[{section_name}]")
                    if data:
                        print_data(data)
                    else:
                        print(f"\tNo {section_name.lower()} found")
            else:
                print(f"\n[{section_name}]")
                if data:
                    print_data(data)
                else:
                    print(f"\tNo {section_name.lower()} found")

    print_section_for_arch("General File Info", macho.get_general_info, args.all, args.general_info)
    
    # Format header data for human-readable display
    def get_formatted_header(arch=None):
        raw_header = macho.get_macho_header(arch)
        if raw_header is None:
            return None
        
        if isinstance(raw_header, dict) and 'magic' in raw_header:
            # Single architecture case
            if arch:
                macho_instance = macho.get_macho_for_arch(arch)
            else:
                macho_instance = macho.macho if hasattr(macho, 'macho') else list(macho.architectures.values())[0] if macho.is_fat else macho
            if macho_instance:
                return macho_instance.format_header_for_display(raw_header)
            return raw_header
        elif isinstance(raw_header, dict):
            # Multi-architecture case
            formatted_data = {}
            for arch_name, arch_header in raw_header.items():
                if arch_header:
                    macho_instance = macho.get_macho_for_arch(arch_name)
                    if macho_instance:
                        formatted_data[arch_name] = macho_instance.format_header_for_display(arch_header)
                    else:
                        formatted_data[arch_name] = arch_header
                else:
                    formatted_data[arch_name] = arch_header
            return formatted_data
        else:
            return raw_header
    
    print_section_for_arch("Mach-O Header", get_formatted_header, args.all, args.header)

    def get_arch_data(attr_name):
        """Get attribute data for target architecture or all architectures."""
        if target_arch:
            macho_instance = macho.get_macho_for_arch(target_arch)
            return getattr(macho_instance, attr_name, None) if macho_instance else None
        else:
            return getattr(macho, attr_name, None)

    # Format load commands for human-readable display
    def get_formatted_load_commands(arch=None):
        raw_load_commands = get_arch_data('load_commands')
        if raw_load_commands is None:
            return None
        
        if isinstance(raw_load_commands, dict) and target_arch is None:
            # Multi-architecture case
            formatted_data = {}
            for arch_name, arch_load_commands in raw_load_commands.items():
                if arch_load_commands:
                    macho_instance = macho.get_macho_for_arch(arch_name)
                    if macho_instance:
                        formatted_data[arch_name] = macho_instance.format_load_commands_for_display(arch_load_commands)
                    else:
                        formatted_data[arch_name] = arch_load_commands
                else:
                    formatted_data[arch_name] = arch_load_commands
            return formatted_data
        else:
            # Single architecture case
            if arch:
                macho_instance = macho.get_macho_for_arch(arch)
            else:
                macho_instance = macho.macho if hasattr(macho, 'macho') else list(macho.architectures.values())[0] if macho.is_fat else macho
            if macho_instance and raw_load_commands:
                return macho_instance.format_load_commands_for_display(raw_load_commands)
            return raw_load_commands

    def get_formatted_load_commands_set(arch=None):
        raw_load_commands_set = get_arch_data('load_commands_set')
        if raw_load_commands_set is None:
            return None
        
        if isinstance(raw_load_commands_set, dict) and target_arch is None:
            # Multi-architecture case
            formatted_data = {}
            for arch_name, arch_set in raw_load_commands_set.items():
                if arch_set:
                    macho_instance = macho.get_macho_for_arch(arch_name)
                    if macho_instance:
                        formatted_data[arch_name] = {macho_instance.format_load_command(cmd) for cmd in arch_set}
                    else:
                        formatted_data[arch_name] = arch_set
                else:
                    formatted_data[arch_name] = arch_set
            return formatted_data
        else:
            # Single architecture case
            if arch:
                macho_instance = macho.get_macho_for_arch(arch)
            else:
                macho_instance = macho.macho if hasattr(macho, 'macho') else list(macho.architectures.values())[0] if macho.is_fat else macho
            if macho_instance and raw_load_commands_set:
                return {macho_instance.format_load_command(cmd) for cmd in raw_load_commands_set}
            return raw_load_commands_set

    if args.all or args.load_cmd_t:
        load_commands = get_formatted_load_commands()
        load_commands_set = get_formatted_load_commands_set()
        
        if target_arch:
            print(f"\n[Load Cmd table - {target_arch}]")
            if load_commands:
                print_list(load_commands)
            else:
                print("\tNo load commands found")
            print(f"\n[Load Commands - {target_arch}]") 
            if load_commands_set:
                print_list(sorted(load_commands_set))
            else:
                print("\tNo load commands found")
        else:
            if macho.is_fat and isinstance(load_commands, dict):
                for arch in available_archs:
                    arch_load_commands = load_commands.get(arch, [])
                    arch_load_commands_set = load_commands_set.get(arch, set())
                    print(f"\n[Load Cmd table - {arch}]")
                    if arch_load_commands:
                        print_list(arch_load_commands)
                    else:
                        print("\tNo load commands found")
                    print(f"\n[Load Commands - {arch}]")
                    if arch_load_commands_set:
                        print_list(sorted(arch_load_commands_set))
                    else:
                        print("\tNo load commands found")
            else:
                print("\n[Load Cmd table]")
                if load_commands:
                    print_list(load_commands)
                else:
                    print("\tNo load commands found")
                print("\n[Load Commands]")
                if load_commands_set:
                    print_list(sorted(load_commands_set))
                else:
                    print("\tNo load commands found")


    # Segments - table formatting
    if args.all or args.segments:
        segments = get_arch_data('segments')
        
        if target_arch:
            print(f"\n[File Segments - {target_arch}]")
            if segments:
                print_list_dict_as_table(segments)
            else:
                print("\tNo segments found")
        elif macho.is_fat and isinstance(segments, dict):
            for arch in available_archs:
                arch_segments = segments.get(arch)
                print(f"\n[File Segments - {arch}]")
                if arch_segments:
                    print_list_dict_as_table(arch_segments)
                else:
                    print("\tNo segments found")
        else:
            print("\n[File Segments]")
            if segments:
                print_list_dict_as_table(segments)
            else:
                print("\tNo segments found")

    # Dylib sections - both commands and names with table formatting
    if args.all or args.dylib:
        commands_data = get_arch_data('dylib_commands')
        names_data = get_arch_data('dylib_names')
        
        if target_arch:
            # Single architecture
            print(f"\n[Dylib Commands - {target_arch}]")
            if commands_data:
                print_list_dict_as_table(commands_data)
            else:
                print("\tNo dylib commands found")
            print(f"\n[Dylib Names - {target_arch}]")
            if names_data:
                print_list(names_data)
            else:
                print("\tNo dylib names found")
        elif macho.is_fat and isinstance(commands_data, dict):
            # Multi-architecture FAT binary
            for arch in available_archs:
                print(f"\n[Dylib Commands - {arch}]")
                arch_commands = commands_data.get(arch)
                if arch_commands:
                    print_list_dict_as_table(arch_commands)
                else:
                    print("\tNo dylib commands found")
                print(f"\n[Dylib Names - {arch}]")
                arch_names = names_data.get(arch)
                if arch_names:
                    print_list(arch_names)
                else:
                    print("\tNo dylib names found")
        else:
            # Single architecture binary
            print("\n[Dylib Commands]")
            if commands_data:
                print_list_dict_as_table(commands_data)
            else:
                print("\tNo dylib commands found")
            print("\n[Dylib Names]")
            if names_data:
                print_list(names_data)
            else:
                print("\tNo dylib names found")

    print_section_for_arch("UUID", lambda arch: get_arch_data('uuid'), args.all, args.uuid)
    print_section_for_arch("Entry Point", lambda arch: get_arch_data('entry_point'), args.all, args.entry_point)
    # Format version info for human-readable display
    def get_formatted_version_info(arch=None):
        raw_version_info = get_arch_data('version_info')
        if raw_version_info is None:
            return None
        
        if isinstance(raw_version_info, dict) and 'platform_cmd' in raw_version_info:
            # Single architecture case
            if arch:
                macho_instance = macho.get_macho_for_arch(arch)
            else:
                macho_instance = macho.macho if hasattr(macho, 'macho') else list(macho.architectures.values())[0] if macho.is_fat else macho
            if macho_instance:
                return macho_instance.format_version_info_for_display(raw_version_info)
            return raw_version_info
        elif isinstance(raw_version_info, dict):
            # Multi-architecture case
            formatted_data = {}
            for arch_name, arch_version_info in raw_version_info.items():
                if arch_version_info:
                    macho_instance = macho.get_macho_for_arch(arch_name)
                    if macho_instance:
                        formatted_data[arch_name] = macho_instance.format_version_info_for_display(arch_version_info)
                    else:
                        formatted_data[arch_name] = arch_version_info
                else:
                    formatted_data[arch_name] = arch_version_info
            return formatted_data
        else:
            return raw_version_info
    
    print_section_for_arch("Version Information", get_formatted_version_info, args.all, args.version)
    print_section_for_arch("Code Signature", lambda arch: get_arch_data('code_signature_info'), args.all, args.signature)

    print_section_for_arch("Imported Functions", macho.get_imported_functions, args.all, args.imports)
    print_section_for_arch("Exported Symbols", macho.get_exported_symbols, args.all, args.exports)
    print_section_for_arch("Similarity Hashes", macho.get_similarity_hashes, args.all, args.similarity)

if __name__ == "__main__":
    main()