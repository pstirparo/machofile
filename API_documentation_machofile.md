# API Documentation for machofile

You can use machofile as python module within your code, here is a brief documentation about the API and how to use them.

## Module version
It expects to be supplied with either a file path or a data buffer to parse.

```python
import machofile
macho = machofile.UniversalMachO(file_path='/path/to/machobinary')
macho.parse()
```

If the data buffer is already available, it can be supplied directly with:

```python
import machofile
with open(file_path, 'rb') as f:
    data = f.read()
macho = machofile.UniversalMachO(data=data)
macho.parse()
```

## API Usage Examples

After parsing with `macho.parse()`, you can extract the same information that the CLI provides using the following methods.

**Important Note on Return Values**: The API returns raw values from the binary file. While the CLI formats these values for human readability (e.g., converting magic numbers to strings like "MH_MAGIC_64"), the API returns the actual numeric values and bytes objects. All integer values from binary structures are unsigned integers, though Python represents them as regular `int` types.

**General Information** (`-g` / `--general_info`):
```python
general_info = macho.get_general_info()
# Returns: {'filename': str, 'filesize': int, 'md5': str, 'sha1': str, 'sha256': str}
```

**Mach-O Header** (`-hdr` / `--header`):
```python
header = macho.get_macho_header()
# Returns: {'magic': int, 'cputype': int, 'cpusubtype': int, 'filetype': int, 
#           'ncmds': int, 'sizeofcmds': int, 'flags': int}
# Note: All integers are unsigned values (uint32_t in C)
```

**Load Commands** (`-l` / `--load_cmd_t`):
```python
# Access via properties:
load_commands = macho.load_commands      # List of {'cmd': int, 'cmdsize': int}
load_commands_set = macho.load_commands_set  # Set of unique command names (strings)
```

**File Segments** (`-seg` / `--segments`):
```python
segments = macho.segments
# Returns: List of segment dictionaries with fields:
# {'segname': str, 'vaddr': int, 'vsize': int, 'offset': int, 'size': int,
#  'max_vm_protection': int, 'initial_vm_protection': int, 'nsects': int, 
#  'flags': int, 'entropy': float}
```

**Dylib Commands** (`-d` / `--dylib`):
```python
dylib_commands = macho.dylib_commands    # List of dylib command dictionaries
# Each dict contains: {'dylib_name_offset': int, 'dylib_timestamp': int,
#                      'dylib_current_version': int, 'dylib_compat_version': int,
#                      'dylib_name': bytes (binary string)}
dylib_names = macho.dylib_names          # List of dylib name bytes objects
```

**UUID** (`-u` / `--uuid`):
```python
uuid = macho.uuid
# Returns: String in format "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
```

**Entry Point** (`-ep` / `--entry-point`):
```python
entry_point = macho.entry_point
# Returns: {'type': str, 'entryoff': int} for LC_MAIN or 
#          {'type': str, 'entry_address': int} for LC_UNIXTHREAD
# TODO: missing thread_data_size
```

**Version Information** (`-v` / `--version`):
```python
version_info = macho.version_info
# Returns: {'platform_cmd': int, 'min_version': int, 'sdk_version': int} or None
```

**Code Signature** (`-sig` / `--signature`):
```python
code_signature_info = macho.code_signature_info
# Returns: Dictionary with signature details, certificates, and entitlements
```

**Imported Functions** (`-i` / `--imports`):
```python
imported_functions = macho.get_imported_functions()
# Returns: Dictionary mapping dylib names (bytes) to lists of imported function names (bytes)
# Example: {b'/usr/lib/libSystem.B.dylib': [b'_malloc', b'_free', ...]}
```

**Exported Symbols** (`-e` / `--exports`):
```python
exported_symbols = macho.get_exported_symbols()
# Returns: Dictionary mapping source names (bytes) to lists of exported symbol names (bytes)
# Example: {b'<unknown>': [b'_main', b'start', ...]}
```

**Similarity Hashes** (`-sim` / `--similarity`):
```python
similarity_hashes = macho.get_similarity_hashes()
# Returns: {'dylib_hash': str, 'import_hash': str, 'export_hash': str, 'symhash': str}
```

### Working with Universal (FAT) Binaries

For Universal binaries containing multiple architectures:

```python
# Get list of architectures
architectures = macho.get_architectures()  # e.g., ['x86_64', 'arm64']

# Get data for specific architecture
header_x86 = macho.get_macho_header(arch='x86_64')
imports_arm64 = macho.get_imported_functions(arch='arm64')

# Access architecture-specific MachO instance
macho_x86 = macho.get_macho_for_arch('x86_64')
```

When accessing properties on a Universal binary without specifying an architecture, 
the data is returned as a dictionary with architecture names as keys:

```python
# For Universal binaries:
segments = macho.segments  # {'x86_64': [...], 'arm64': [...]}
uuid = macho.uuid         # {'x86_64': 'uuid-string', 'arm64': 'uuid-string'}
```