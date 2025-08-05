# API Documentation for machofile

You can use `machofile` as python module within your code, here is a brief documentation about the API and how to use them.

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

**Important Note on Return Values**: The API returns raw values from the binary file by default. However, you can now get human-readable formatted values by using the `formatted=True` parameter on most methods. While the CLI formats these values for human readability (e.g., converting magic numbers to strings like "MH_MAGIC_64"), the API can return either raw or formatted values. All integer values from binary structures are unsigned integers, though Python represents them as regular `int` types.

**General Information** (`-g` / `--general_info`):
```python
# Raw data (default)
general_info = macho.get_general_info()
# Returns: {'Filename': str, 'Filesize': int, 'MD5': str, 'SHA1': str, 'SHA256': str}

# Formatted data (same as raw for general info)
general_info = macho.get_general_info(formatted=True)
# Returns: {'Filename': str, 'Filesize': int, 'MD5': str, 'SHA1': str, 'SHA256': str}
```

**Mach-O Header** (`-hdr` / `--header`):
```python
# Raw data (default)
header = macho.get_macho_header()
# Returns: {'magic': int, 'cputype': int, 'cpusubtype': int, 'filetype': int, 
#           'ncmds': int, 'sizeofcmds': int, 'flags': int}

# Formatted data (human-readable)
header = macho.get_macho_header(formatted=True)
# Returns: {'magic': str, 'cputype': str, 'cpusubtype': str, 'filetype': str, 
#           'ncmds': int, 'sizeofcmds': int, 'flags': str}
# Example: {'magic': 'MH_MAGIC_64 (64-bit), 0xFEEDFACF', 'cputype': 'x86_64', ...}
```

**Load Commands** (`-l` / `--load_cmd_t`):
```python
# Raw data (default)
load_commands = macho.get_load_commands()
# Returns: List of {'cmd': int, 'cmdsize': int}
# Example: [{'cmd': 25, 'cmdsize': 72}, {'cmd': 2, 'cmdsize': 24}]

# Formatted data (human-readable)
load_commands = macho.get_load_commands(formatted=True)
# Returns: List of {'cmd': str, 'cmdsize': int}
# Example: [{'cmd': 'LC_SEGMENT_64', 'cmdsize': 72}, {'cmd': 'LC_SYMTAB', 'cmdsize': 24}]

# Load commands set
load_commands_set = macho.get_load_commands_set()  # Raw: Set of int values
load_commands_set = macho.get_load_commands_set(formatted=True)  # Formatted: List of sorted command names
```

**File Segments** (`-seg` / `--segments`):
```python
segments = macho.get_segments()
# Returns: List of segment dictionaries with fields:
# {'segname': str, 'vaddr': int, 'vsize': int, 'offset': int, 'size': int,
#  'max_vm_protection': int, 'initial_vm_protection': int, 'nsects': int, 
#  'flags': int, 'entropy': float}
```

**Dylib Commands** (`-d` / `--dylib`):
```python
dylib_commands = macho.get_dylib_commands()    # List of dylib command dictionaries
# Each dict contains: {'dylib_name_offset': int, 'dylib_timestamp': int,
#                      'dylib_current_version': int, 'dylib_compat_version': int,
#                      'dylib_name': bytes (binary string)}
dylib_names = macho.get_dylib_names()          # List of dylib name bytes objects
```

**UUID** (`-u` / `--uuid`):
```python
uuid = macho.get_uuid()
# Returns: String in format "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
```

**Entry Point** (`-ep` / `--entry-point`):
```python
entry_point = macho.get_entry_point()
# Returns: {'type': str, 'entryoff': int} for LC_MAIN or 
#          {'type': str, 'entry_address': int} for LC_UNIXTHREAD
```

**Version Information** (`-v` / `--version`):
```python
# Raw data (default)
version_info = macho.get_version_info()
# Returns: {'platform_cmd': int, 'min_version': int, 'sdk_version': int} or None

# Formatted data (human-readable)
version_info = macho.get_version_info(formatted=True)
# Returns: {'platform_cmd': str, 'min_version': str, 'sdk_version': str} or None
# Example: {'platform_cmd': 'macOS', 'min_version': '10.15.0', 'sdk_version': '13.0.0'}
```

**Code Signature** (`-sig` / `--signature`):
```python
code_signature_info = macho.get_code_signature_info()
# Returns: code_signature_info dictionary with signed (bool), signing_status (string), certificates_info (dict), entitlements_info (dict), code_directory (dict)
```

**Imported Functions** (`-i` / `--imports`):
```python
# Raw data (default)
imported_functions = macho.get_imported_functions()
# Returns: Dictionary mapping dylib names (bytes) to lists of imported function names (bytes)
# Example: {b'/usr/lib/libSystem.B.dylib': [b'_malloc', b'_free', ...]}

# Formatted data (same as raw for imported functions)
imported_functions = macho.get_imported_functions(formatted=True)
# Returns: Same format as raw data (imported functions are already human-readable)
```

**Exported Symbols** (`-e` / `--exports`):
```python
# Raw data (default)
exported_symbols = macho.get_exported_symbols()
# Returns: Dictionary mapping source names (bytes) to lists of exported symbol names (bytes)
# Example: {b'<unknown>': [b'_main', b'start', ...]}

# Formatted data (same as raw for exported symbols)
exported_symbols = macho.get_exported_symbols(formatted=True)
# Returns: Same format as raw data (exported symbols are already human-readable)
```

**Similarity Hashes** (`-sim` / `--similarity`):
```python
# Raw data (default)
similarity_hashes = macho.get_similarity_hashes()
# Returns: {'dylib_hash': str, 'import_hash': str, 'export_hash': str, 'entitlement_hash': str, 'symhash': str}

# Formatted data (same as raw for similarity hashes)
similarity_hashes = macho.get_similarity_hashes(formatted=True)
# Returns: Same format as raw data (hashes are already in readable hex format)
```

**Individual Hash Methods** (for specific hash types):
```python
# Dylib hash - MD5 of sorted, deduplicated dynamic library names
dylib_hash = macho.get_dylib_hash(arch='x86_64')  # For specific architecture
dylib_hash = macho.get_dylib_hash()               # For single arch or combined (FAT)
dylib_hash = macho.get_dylib_hash(formatted=True) # Same as raw (hashes are already readable)

# Import hash - MD5 of sorted, deduplicated imported function names
import_hash = macho.get_import_hash(arch='x86_64')  # For specific architecture
import_hash = macho.get_import_hash()               # For single arch or combined (FAT)
import_hash = macho.get_import_hash(formatted=True) # Same as raw (hashes are already readable)

# Export hash - MD5 of sorted, deduplicated exported symbol names
export_hash = macho.get_export_hash(arch='x86_64')  # For specific architecture
export_hash = macho.get_export_hash()               # For single arch or combined (FAT)
export_hash = macho.get_export_hash(formatted=True) # Same as raw (hashes are already readable)

# Entitlement hash - MD5 of sorted, deduplicated entitlement names and array values
entitlement_hash = macho.get_entitlement_hash(arch='x86_64')  # For specific architecture
entitlement_hash = macho.get_entitlement_hash()               # For single arch or combined (FAT)
entitlement_hash = macho.get_entitlement_hash(formatted=True) # Same as raw (hashes are already readable)

# Symhash - MD5 of sorted, deduplicated external undefined symbols
symhash = macho.get_symhash(arch='x86_64')  # For specific architecture
symhash = macho.get_symhash()               # For single arch or combined (FAT)
symhash = macho.get_symhash(formatted=True) # Same as raw (hashes are already readable)
```

### Working with Universal (FAT) Binaries

For Universal binaries containing multiple architectures:

```python
# Get list of architectures
architectures = macho.get_architectures()  # e.g., ['x86_64', 'arm64']

# Get data for specific architecture
header_x86 = macho.get_macho_header(arch='x86_64')
header_x86_formatted = macho.get_macho_header(arch='x86_64', formatted=True)
imports_arm64 = macho.get_imported_functions(arch='arm64')

# Access architecture-specific MachO instance
macho_x86 = macho.get_macho_for_arch('x86_64')
```

When accessing methods on a Universal binary without specifying an architecture, 
the data is returned as a dictionary with architecture names as keys:

```python
# For Universal binaries:
segments = macho.get_segments()  # {'x86_64': [...], 'arm64': [...]}
uuid = macho.get_uuid()         # {'x86_64': 'uuid-string', 'arm64': 'uuid-string'}
```

## Complete List of Available Methods

All the following methods are available on the `UniversalMachO` instance and handle both single-architecture and Universal binaries automatically. All methods support the `formatted` parameter for human-readable output:

```python
# Core Mach-O structures
macho.get_load_commands(formatted=False)        # List of load command dictionaries
macho.get_load_commands_set(formatted=False)    # Set of unique load command names
macho.get_segments(formatted=False)            # List of segment dictionaries with entropy

# Dynamic library information
macho.get_dylib_commands(formatted=False)      # List of dylib command dictionaries
macho.get_dylib_names(formatted=False)         # List of dylib name bytes objects

# Binary metadata
macho.get_uuid(formatted=False)                # UUID string
macho.get_entry_point(formatted=False)         # Entry point information
macho.get_version_info(formatted=False)        # Version information

# Code signing and entitlements
macho.get_code_signature_info(formatted=False) # Code signature details, certificates, entitlements

# Import/export analysis
macho.get_imported_functions(formatted=False)  # Dictionary of imported functions by dylib
macho.get_exported_symbols(formatted=False)    # Dictionary of exported symbols

# Similarity hashes
macho.get_similarity_hashes(formatted=False)   # All similarity hashes
macho.get_dylib_hash(formatted=False)          # Dylib hash
macho.get_import_hash(formatted=False)         # Import hash
macho.get_export_hash(formatted=False)         # Export hash
macho.get_entitlement_hash(formatted=False)    # Entitlement hash
macho.get_symhash(formatted=False)             # Symhash
```

**Note**: For Universal binaries, these methods return dictionaries with architecture names as keys. For single-architecture binaries, they return the data directly. The `formatted` parameter provides human-readable output where applicable (e.g., load command names instead of numbers).

## machofile Properties for Backward Compatibility (DEPRECATED)

We have moved all data access to getter methods to better serve content via formatted options. The getter methods are the **advised way** of using the API as they provide:

- **Formatted output support** via the `formatted` parameter
- **Consistent API design** across all data types
- **Better future extensibility** for additional formatting options

**Properties will remain available for backward compatibility reasons but will be removed in future major releases.**

### Available Properties (Legacy API)

```python
# Core Mach-O structures
macho.load_commands        # List of load command dictionaries
macho.load_commands_set    # Set of unique load command names
macho.segments            # List of segment dictionaries with entropy

# Dynamic library information
macho.dylib_commands      # List of dylib command dictionaries
macho.dylib_names         # List of dylib name bytes objects

# Binary metadata
macho.uuid                # UUID string
macho.entry_point         # Entry point information
macho.version_info        # Version information

# Code signing and entitlements
macho.code_signature_info # Code signature details, certificates, entitlements
macho.entitlements        # Entitlements dictionary

# Import/export analysis
macho.imported_functions  # Dictionary of imported functions by dylib
macho.exported_symbols    # Dictionary of exported symbols
```

## Formatted vs Raw Output

The API provides two output modes for most methods:

### Raw Output (Default)
Returns the actual binary values as they appear in the file:
- Magic numbers as integers (e.g., `4277009103`)
- Load command types as integers (e.g., `25` for `LC_SEGMENT_64`)
- CPU types as integers (e.g., `16777223` for `x86_64`)
- Platform types as integers (e.g., `1` for `macOS`)

### Formatted Output (`formatted=True`)
Returns human-readable values:
- Magic numbers as strings (e.g., `"MH_MAGIC_64 (64-bit), 0xFEEDFACF"`)
- Load command types as strings (e.g., `"LC_SEGMENT_64"`)
- CPU types as strings (e.g., `"x86_64"`)
- Platform types as strings (e.g., `"macOS"`)

### Fields That Benefit from Formatting
- **Headers**: Magic, CPU type, CPU subtype, file type, flags
- **Load Commands**: Command types and names
- **Load Commands Set**: Sorted list of command names
- **Version Info**: Platform names and version strings

### Fields That Are Identical in Both Modes
- **General Info**: Already human-readable (filename, hashes, etc.)
- **UUID**: Already in readable format
- **Imported Functions**: Already human-readable function names
- **Exported Symbols**: Already human-readable symbol names
- **Similarity Hashes**: Already in readable hex format
- **Segments**: Already in readable format
- **Dylib Info**: Already human-readable
- **Entry Point**: Already in readable format
- **Code Signature Info**: Already in readable format

For fields that are identical in both modes, the `formatted` parameter is ignored for consistency.

### Combined Similarity Hashes for Universal Binaries

For Universal binaries, the similarity hashes include combined hashes that merge data from all architectures:

```python
similarity_hashes = macho.get_similarity_hashes()
# Returns: {
#   'x86_64': {'dylib_hash': str, 'import_hash': str, 'export_hash': str, 'entitlement_hash': str, 'symhash': str},
#   'arm64': {'dylib_hash': str, 'import_hash': str, 'export_hash': str, 'entitlement_hash': str, 'symhash': str},
#   'combined': {'dylib_hash': str, 'import_hash': str, 'export_hash': str, 'entitlement_hash': str, 'symhash': str}
# }
```