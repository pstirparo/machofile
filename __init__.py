"""
machofile - A Python module to parse Mach-O binary files

machofile is a self-contained Python module for parsing Mach-O binary files, 
with a focus on malware analysis and reverse engineering. It's self-contained 
with no dependencies, endianness independent, and works on macOS, Windows, 
and Linux.

Author: Pasquale Stirparo
License: MIT
"""

from .machofile import UniversalMachO, MachO, main

__version__ = "2025.07.30"
__author__ = "Pasquale Stirparo"
__license__ = "MIT"

__all__ = ["UniversalMachO", "MachO", "main"] 