#!/usr/bin/python
import sys
import os
from elf_info_class import elfInfo

if len(sys.argv) == 1:
	sys.exit("No argument provided\nUsage : elf_info.py elf_file[ elf_file2 ...]")
for i in sys.argv[1:]:
	my_elf = elfInfo(i)
	my_elf.parse()
	if i != sys.argv[1]:
		print("\n" + "=" * 20 + "\n")
	my_elf.print()
