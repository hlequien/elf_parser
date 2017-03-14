# eflInfo
elfInfo is pyhton class to parse ELF binaries, realeased with two examples : `elf_info.py` and `shellcode_extractor.py`

## Examples

### elf_info.py
`elf_info.py` is a script to parse and print ELF header and section headers

### shellcode_extractor.py
`shellcode_extractor.py` is a script to parse an ELF file, check if it's a relocatable object and if so print the shellcode in an easily usable format ("\x01\x02\x03...") on the standard output.
