#!/usr/bin/python3
import sys
import os
from elf_info_class import elfInfo

def elfGetShellcode(elf):
	if elf == None:
		return(1)
	if elf.parsed == 0:
		return(2)
	text_sh = 0
	for i in elf.sh_list:
		if i.name == ".text":
			text_sh = i
			break
	f = open(elf.file, 'rb')
	f.seek(i.sh_offset)
	shellcode = f.read(i.sh_size)
	f.close
	sh_str = ''
	for i in range(0, len(shellcode)):
		sh_str = sh_str + "\\x" + shellcode[i:i + 1].hex()
	return(sh_str)

if len(sys.argv) < 2:
	print("No argument provided\nUsage : " + sys.argv[0] + " [options] shellcode_file.o")
	sys.exit(1)
shellcodeElf = elfInfo(sys.argv[1])
shellcodeElf.parse()
if shellcodeElf.type != "relocatable object":
	print(sys.argv[1] + " is not an object")
	sys.exit(2)
print(elfGetShellcode(shellcodeElf))