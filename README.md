# machofile
machofile is a module to parse Mach-O binary files

Inspired by Ero Carrera's pefile, this module aims to provide a similar capability but for Mach-O binaries instead. 
Reference material and documentation used to gain the file format knowledge, the basic structures and constant are taken from the resources listed below.

machofile is self-contained. The module has no dependencies; it is endianness independent; and it works on macOS, Windows, and Linux.

While there are other mach-o parsing modules out there, the motivations behind developing this one are:
- first and foremost, for me this was a great way to deep dive and learn more about the Mach-O format and structures
- to provide a simple way to parse Mach-O files for analysis
- to not depend on external modules (e.g. lief, macholib, macho, etc.), since everything is directly extracted from the file and is all in pure python.

This is the very first/alpha version still (2023.11.04), so please let me know if you try or find bugs but also be gentle ;) code will be optimized and more features will be added in the near future.

**Current Features:**
- Parse Mach-O Header
- Parse Load Commands
- Parse File Segments
- Parse Dylib Commands
- Parse Dylib List

_Note: as of now, this has initially be tested against x86 and x86_64 Mach-O samples._

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
- Ero Carrera ([@erocarrera](https://twitter.com/erocarrera)) for writing and maintaining the [pefile](https://github.com/erocarrera/pefile/tree/master) module
- Patrick Wardle ([@patrickwardle](https://twitter.com/patrickwardle)) for the great work in sharing his macOS malware analysis and research, and brigning to life [OBTS](https://objectivebythesea.org/) :)
- Greg Lesnewich ([@greglesnewich](https://twitter.com/greglesnewich)) for his work on [macho-similarity](https://github.com/g-les/macho_similarity)

## Usage and example
You can either use it from command line or import it as a module in your python code, and call each function individually to parse only the structures you are interested in.

### Module version
It expect to be supplied with either a file path or a data buffer to parse.

```
import machofile
macho = MachO(file_path='/path/to/machobinary')
macho = MachO('/path/to/machobinary')
```
The above two lines are equivalent and would load the Mach-O file and parse it.
If the data buffer is already available, it can be supplied directly with:

```
import machofile
macho = MachO(data=bytes_variable)
```

You will then need to invoke the `parse()` method to start the parsing process,
and can then call each function individually to parse only the structures you are interested in.

```
macho.parse()
dylib_cmd_list, dylib_lst = macho.get_dylib_commands()
...
```

### Command Line version
You can now use `machofile.py` directly as a CLI tool. All CLI features are available from the same file you import as a module.

```
% python3 machofile.py -h
usage: machofile.py [-h] -f FILE [-a] [-i] [-hd] [-l] [-sg] [-d] [-sm]

Parse Mach-O file structures.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to the file to be parsed
  -a, --all             Print all info about the file
  -i, --info            Print general info about the file
  -hd, --header         Print Mach-O header info
  -l, --load_cmd_t      Print Load Command Table and Command list
  -sg, --segments       Print File Segments info
  -d, --dylib           Print Dylib Command Table and Dylib list
  -sm, --similarity     Print similarity hashes
```

Example output:
```
% python3 machofile.py -a -f b4f68a58658ceceb368520dafc35b270272ac27b8890d5b3ff0b968170471e2b 

[General File Info]
        Filename:    b4f68a58658ceceb368520dafc35b270272ac27b8890d5b3ff0b968170471e2b
        Filesize:    54240
        Filetype:    EXECUTE
        Flags:       NOUNDEFS, DYLDLINK, TWOLEVEL
        MD5:         20ffe440e4f557b9e03855b5da2b3c9c
        SHA1:        1bf61ecad8568a774f9fba726a254a9603d09f33
        SHA256:      b4f68a58658ceceb368520dafc35b270272ac27b8890d5b3ff0b968170471e2b

[Mach-O Header]
        magic:       MH_MAGIC (32-bit), 0xFEEDFACE
        cputype:     Intel i386
        cpusubtype:  x86_ALL, x86_64_H, x86_64_LIB64
        filetype:    EXECUTE
        ncmds:       13
        sizeofcmds:  1180
        flags:       NOUNDEFS, DYLDLINK, TWOLEVEL

[Load Cmd table]
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

[Load Commands]
        LC_CODE_SIGNATURE
        LC_DYSYMTAB
        LC_LOAD_DYLIB
        LC_LOAD_DYLINKER
        LC_SYMTAB
        LC_UNIXTHREAD
        LC_UUID

[File Segments]
        SEGNAME    VADDR VSIZE OFFSET SIZE  MAX_VM_PROTECTION INITIAL_VM_PROTECTION NSECTS FLAGS
        ----------------------------------------------------------------------------------------
        __PAGEZERO 0     4096  0      0     0                 0                     0      0    
        __TEXT     4096  28672 0      28672 7                 5                     2      0    
        __DATA     32768 4096  28672  4096  7                 3                     4      0    
        __IMPORT   36864 4096  32768  4096  7                 7                     2      0    
        __LINKEDIT 40960 20480 36864  17376 7                 1                     0      0    

[Dylib Commands]
        DYLIB_NAME_OFFSET DYLIB_TIMESTAMP DYLIB_CURRENT_VERSION DYLIB_COMPAT_VERSION DYLIB_NAME                   
        ----------------------------------------------------------------------------------------------------------
        24                2               65536                 65536                b'/usr/lib/libgcc_s.1.dylib' 
        24                2               7274759               65536                b'/usr/lib/libSystem.B.dylib'

[Dylib Names]
        b'/usr/lib/libgcc_s.1.dylib'
        b'/usr/lib/libSystem.B.dylib'

[Similarity Hashes]
        dylib_hash:  0556bed5dc31bddaee73f3234b3c577b
```

## Reference/Documentation links:
- https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
- https://github.com/apple-oss-distributions/lldb/blob/10de1840defe0dff10b42b9c56971dbc17c1f18c/llvm/include/llvm/Support/MachO.h
- https://iphonedev.wiki/Mach-O_File_Format
- https://lowlevelbits.org/parsing-mach-o-files/
- https://github.com/aidansteele/osx-abi-macho-file-format-reference
- https://lief-project.github.io/doc/latest/tutorials/11_macho_modification.html
- https://github.com/VirusTotal/yara/blob/master/libyara/include/yara/macho.h
- https://github.com/corkami/pics/blob/master/binary/README.md
- https://github.com/qyang-nj/llios/tree/main
