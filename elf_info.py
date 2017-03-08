#!/usr/bin/python
import sys
import os
from elf_info_class import elfInfo

if len(sys.argv) == 1:
	sys.exit("No argument provided")
for i in sys.argv[1:]:
	my_elf = elfInfo(i)
	my_elf.parse()
	my_elf.print()
