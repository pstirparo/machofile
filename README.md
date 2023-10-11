# machofile
machofile is a module to parse Mach-O binary files

Inspired by Ero Carrera's pefile, this module aims to provide a similar capability but for Mach-O binaries instead. 
Reference material and documentation used to gain the file format knowledge, the basic structures and constant are taken from the resources listed below.

machofile is self-contained. The module has no dependencies; it is endianness independent; and it works on macOS, Windows, and Linux.

While there are other mach-o parsing modules out there, the motivations behind developing this one are:
- first and foremost, for me this was a great way to deep dive and learn more about the Mach-O format and structures
- to provide a simple way to parse Mach-O files for analysis
- to not depend on external modules (e.g. lief, macholib, macho, etc.), since everything is directly extracted from the file and is all in pure python.

This is the very first/alpha version still (2023.10.10), so please let me know if you try or find bugs but also be gentle ;) code will be optimized and more features will be added in the near future.

**Current Features:**
- Parse Mach-O Header
- Parse Load Commands
- Parse File Segments
- Parse Dylib Commands
- Parse Dylib List

**Next features to be implemented:**
- extract Entry Point 
- Parse Code Signature information
- Embedded strings
- File Attributes
- data entropy calculation
- flag for suspicious libraries
- Packer detection
- Hashes: dylib hash, import hash, export hash, ...
- prettify output to console
- add output option to yaml and json
- add options to parse only specific structures

## Credits
Those are the people that I would like to thank for being the inspiration that led me to write this module:
- Ero Carrera ((@erocarrera)[https://twitter.com/erocarrera]) for writing and maintaining the [pefile](https://github.com/erocarrera/pefile/tree/master) module
- Patrick Wardle ((@patrickwardle)[https://twitter.com/patrickwardle]) for the great work in sharing his macOS malware analysis and research, and brigning to life (OBTS)[https://objectivebythesea.org/] :)
- Greg Lesnewich ((@greglesnewich)[https://twitter.com/greglesnewich]) for his work on (macho-similarty)[https://github.com/g-les/macho_similarity]

## Usage and example
You can either use it from command line or import it as a module in your python code, and call each function individually to parse only the structures you are interested in.

From CLI, at the moment it just retireves all the structures parsed, in the future there will be flags to just get one specific structure or a list of them.
```
% python3 machofile.py -h
usage: machofile.py [-h] -f FILE

Parse Mach-O file structures.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to the file to be parsed
```

Example output:
```
% python3 machofile.py ./b4f68a58658ceceb368520dafc35b270272ac27b8890d5b3ff0b968170471e2b

Getting general info...
	MD5: : 20ffe440e4f557b9e03855b5da2b3c9c
	SHA256: : b4f68a58658ceceb368520dafc35b270272ac27b8890d5b3ff0b968170471e2b

Parsing Mac-O Header...
	magic: MH_MAGIC (32-bit)
	cputype: Intel i386
	cpusubtype: x86_ALL, x86_64_H, x86_64_LIB64
	filetype: MH_EXECUTE
	ncmds: 13
	sizeofcmds: 1180
	flags: MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL

Parsing Load Cmd table...
	{'cmd': 'LC_SEGMENT', 'cmdsize': 56}
	{'cmd': 'LC_SEGMENT', 'cmdsize': 192}
	{'cmd': 'LC_SEGMENT', 'cmdsize': 328}
	{'cmd': 'LC_SEGMENT', 'cmdsize': 192}
	{'cmd': 'LC_SEGMENT', 'cmdsize': 56}
	{'cmd': 'LC_SYMTAB', 'cmdsize': 24}
	{'cmd': 'LC_DYSYMTAB', 'cmdsize': 80}
	{'cmd': 'LC_LOAD_DYLINKER', 'cmdsize': 28}
	{'cmd': 'LC_UUID', 'cmdsize': 24}
	{'cmd': 'LC_UNIXTHREAD', 'cmdsize': 80}
	{'cmd': 'LC_LOAD_DYLIB', 'cmdsize': 52}
	{'cmd': 'LC_LOAD_DYLIB', 'cmdsize': 52}
	{'cmd': 'LC_CODE_SIGNATURE', 'cmdsize': 16}

Load Commands:
	LC_CODE_SIGNATURE
	LC_DYSYMTAB
	LC_LOAD_DYLIB
	LC_LOAD_DYLINKER
	LC_SYMTAB
	LC_UNIXTHREAD
	LC_UUID

File Segments:
	segname: __PAGEZERO
	vaddr: 0
	vsize: 4096
	offset: 0
	size: 0
	max_vm_protection: 0
	initial_vm_protection: 0
	nsects: 0
	flags: 0

	segname: __TEXT
	vaddr: 4096
	vsize: 28672
	offset: 0
	size: 28672
	max_vm_protection: 7
	initial_vm_protection: 5
	nsects: 2
	flags: 0

	segname: __DATA
	vaddr: 32768
	vsize: 4096
	offset: 28672
	size: 4096
	max_vm_protection: 7
	initial_vm_protection: 3
	nsects: 4
	flags: 0

	segname: __IMPORT
	vaddr: 36864
	vsize: 4096
	offset: 32768
	size: 4096
	max_vm_protection: 7
	initial_vm_protection: 7
	nsects: 2
	flags: 0

	segname: __LINKEDIT
	vaddr: 40960
	vsize: 20480
	offset: 36864
	size: 17376
	max_vm_protection: 7
	initial_vm_protection: 1
	nsects: 0
	flags: 0

Parsing Dylib Cmd table...
	dylib_name_offset: 24
	dylib_timestamp: 2
	dylib_current_version: 65536
	dylib_compat_version: 65536
	dylib_name: b'/usr/lib/libgcc_s.1.dylib'

	dylib_name_offset: 24
	dylib_timestamp: 2
	dylib_current_version: 7274759
	dylib_compat_version: 65536
	dylib_name: b'/usr/lib/libSystem.B.dylib'

Parsing Dylib List...
	b'/usr/lib/libgcc_s.1.dylib'
	b'/usr/lib/libSystem.B.dylib'
```

## Reference/Documentation links:
- https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
- https://github.com/apple-oss-distributions/lldb/blob/10de1840defe0dff10b42b9c56971dbc17c1f18c/llvm/include/llvm/Support/MachO.h
- https://iphonedev.wiki/Mach-O_File_Format
- https://lowlevelbits.org/parsing-mach-o-files/
- https://github.com/aidansteele/osx-abi-macho-file-format-reference
- https://lief-project.github.io/doc/latest/tutorials/11_macho_modification.html
- https://github.com/VirusTotal/yara/blob/master/libyara/include/yara/macho.h

