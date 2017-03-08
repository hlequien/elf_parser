import sys
import os

class sectionHeader():
	"""docstring for sectionHeader"""

	def gen_sh_type_dict(self):
		sh_type_dict = {b'\x00\x00\x00\x00' : "SHT_NULL : Section header table entry unused",
		b'\x00\x00\x00\x01' : "SHT_PROGBITS : Program data",
		b'\x00\x00\x00\x02' : "SHT_SYMTAB : Symbol table",
		b'\x00\x00\x00\x03' : "SHT_STRTAB : String table",
		b'\x00\x00\x00\x04' : "SHT_RELA : Relocation entries with addends",
		b'\x00\x00\x00\x05' : "SHT_HASH : Symbol hash table",
		b'\x00\x00\x00\x06' : "SHT_DYNAMIC : Dynamic linking information",
		b'\x00\x00\x00\x07' : "SHT_NOTE : Notes",
		b'\x00\x00\x00\x08' : "SHT_NOBITS : Program space with no data (bss)",
		b'\x00\x00\x00\x09' : "SHT_REL : Relocation entries, no addends",
		b'\x00\x00\x00\x0A' : "SHT_SHLIB : Reserved",
		b'\x00\x00\x00\x0B' : "SHT_DYNSYM : Dynamic linker symbol table",
		b'\x00\x00\x00\x0E' : "SHT_INIT_ARRAY : Array of constructors",
		b'\x00\x00\x00\x0F' : "SHT_FINI_ARRAY : Array of destructors",
		b'\x00\x00\x00\x10' : "SHT_PREINIT_ARRAY : Array of pre-constructors",
		b'\x00\x00\x00\x11' : "SHT_GROUP : Section group",
		b'\x00\x00\x00\x12' : "SHT_SYMTAB_SHNDX : Extended section indeces",
		b'\x00\x00\x00\x13' : "SHT_NUM : Number of defined types.",
		b'\x60\x00\x00\x00' : "SHT_LOOS : Start OS-specific."}
		return(sh_type_dict)

	def setName(self, elf, file):
		shstrndx = elf.sh_list[elf.shstrndx]
		nameAddr = shstrndx.sh_offset + self.sh_name
		#print("nameAddr = " + str(hex(nameAddr + int.from_bytes(shstrndx.sh_entsize, 'big'))))
		file.seek(nameAddr)
		last_char = 'a'
		self.name = ""
		while last_char != '\x00':
			last_char = file.read(1).decode('ascii')
			if last_char != '\x00':
				self.name = self.name + last_char
		if self.name == "":
			self.name = "Unknown"

	def process_parse(self, elf):
		sh_type_dict = self.gen_sh_type_dict()
		if self.sh_type in sh_type_dict:
			self.sh_type = sh_type_dict[self.sh_type]
		else:
			self.sh_type = "Unknown : " + hex(self.sh_type)


	def __init__(self, b_array, elf):
		if elf == None or len(b_array) != elf.shentsize:
			return(None)
		members_list = ["sh_name", "sh_type", "sh_flags", "sh_addr", "sh_offset", "sh_size", "sh_link", "sh_info", "sh_addralign", "sh_entsize"]
		self.sh_name = 4
		self.sh_type = 4
		self.sh_flags = 8
		self.sh_addr = 8
		self.sh_offset = 8
		self.sh_size = 8
		self.sh_link = 4
		self.sh_info = 4
		self.sh_addralign = 8
		self.sh_entsize = 8
		self.name = "Unknown"
		addr_size = elf.bits * 4
		offset = 0
		for i in range(0, len(members_list)):
			if getattr(self, members_list[i]) == 8 and addr_size == 4:
				setattr(self, members_list[i], b_array[offset:offset + addr_size])
				offset += addr_size
			else:
				offset += getattr(self, members_list[i])
				setattr(self, members_list[i], b_array[offset - getattr(self, members_list[i]):offset])
			if elf.endianness == 1:
				setattr(self, members_list[i], getattr(self, members_list[i])[::-1])
			#print("members_list[i] = " + str(i) + str(members_list[i]))
		self.process_parse(elf)
		for i in members_list:
			if isinstance(getattr(self, i), bytes):
				setattr(self, i, int.from_bytes(getattr(self, i), 'big'))

	def print(self):
		print("The name of the section is at index : " + str(self.sh_name))
		print("The name is : " + str(self.name))
		print("Type : " + str(self.sh_type))
		print("Flags : " + str(self.sh_flags))
		print("Virtual address in memory : " + str(self.sh_addr))
		print("Offset in the file image : " + str(self.sh_offset))
		print("Size in the file image : " + str(self.sh_size))
		print("sh_link : " + str(self.sh_link))
		print("sh_info : " + str(self.sh_info))
		print("sh_addralign : " + str(self.sh_addralign))
		print("sh_entsize : " + str(self.sh_entsize))

class programHeader():
	"""docstring for programHeader"""
	p_type = ""
	p_offset = ""
	p_vaddr = ""
	p_paddr = ""
	p_filesz = ""
	p_memsz = ""
	p_flags = ""
	p_align = ""

	def __init__(self, b_array, elf):
		if elf == None or len(b_array) != elf.phentsize:
			return(None)
		members = vars(self)
		addr_size = elf.bits / 8
		for i in range(0, len(members)):
			setattr(self, members[i], b_array[i * addr_size:(i + 1) * addr_size])

class elfInfo():
	"""elfInfo is designed to parse and store informations about an ELF file"""
	def __init__(self, file):
		self.filename = os.path.basename(file)
		self.file = file
		self.parsed = 0
	# dictionary generators
	def gen_abi_dict(self):
		abi_dict = {0x00: "System V", 0x01: "HP-UX", 0x02: "NetBSD",
		0x03: "Linux", 0x06: "Solaris", 0x07: "AIX", 0x08: "IRIX",
		0x09: "FreeBSD", 0x0a: "Tru64", 0x0b: "Novell Modesto",
		0x0c: "OpenBSD", 0x0d: "OpenVMS", 0x0e: "NonStop Kernel",
		0x0f: "AROS", 0x10: "Fenix OS", 0x11: "CloudABI", 0x53: "Sortix"}
		return(abi_dict)

	def gen_type_dict(self):
		type_dict = {b'\x00\x01': "relocatable object", b'\x00\x02': "executable", b'\x00\x03': "shared object",
		b'\x00\x04': "core"}
		return(type_dict)

	def gen_arch_dict(self):
		arch_dict = {b'\x00\x00': "unspecified", b'\x00\x02': "SPARC", b'\x00\x03': "x86",
		b'\x00\x08': "MIPS", b'\x00\x14': "PowerPC", b'\x00\x28': "ARM", b'\x00\x2a': "SuperH",
		b'\x00\x32': "IA-64", b'\x00\x3e': "x86-64", b'\x00\xb7': "AArch64", b'\x00\xf3': "RISC-V"}
		return(arch_dict)

	def process_parse(self):
		if self.magic_nb != b'\x7fELF':
			print("elfInfo: " + self.filename + ": Not an ELF", file=sys.stderr)
			return(-1)
		self.magic_nb = "ELF"
		if self.bits == 1:
			self.bits = 32
		elif self.bits == 2:
			self.bits = 64
		else:
			self.bits = "unkown"
		if self.endianness == 1:
			self.endianness = "little endian"
		elif self.endianness == 2:
			self.endianness = "big endian"
		else:
			self.endianness = "unknown : " + str(self.endianness)
		#no treatment for orinal ELF
		abi_dict = self.gen_abi_dict()
		if self.os_abi in abi_dict:
			self.os_abi = abi_dict[self.os_abi]
		else:
			self.os_abi = "Unknown"
		type_dict = self.gen_type_dict()
		if self.type in type_dict:
			self.type = type_dict[self.type]
		else:
			self.type = "unknown"
		arch_dict = self.gen_arch_dict()
		if self.endianness == "little endian":
			self.inst_arch[::-1]
		if self.inst_arch in arch_dict:
			self.inst_arch = arch_dict[self.inst_arch]
		else:
			self.inst_arch = "unknown : " + str(self.inst_arch.hex())

	def parse(self):
		if not os.path.isfile(self.file):
			print("elfInfo: " + self.filename + ": not a file", file=sys.stderr)
			return(-1)
		if not os.access(self.file, os.R_OK):
			print("elfInfo: " + self.filename + ": not readable", file=sys.stderr)
			return(-2)
		f = open(self.file, 'rb')
		# read the first part of the ELF header
		tmp = f.read(0x18)
		self.magic_nb = tmp[:4]
		self.bits = tmp[4]
		self.endianness = tmp[5]
		self.os_abi = tmp[7]
		self.type = tmp[0x10:0x12]
		self.inst_arch = tmp[0x12:0x14]
		addr_size = 4 * self.bits
		tmp = f.read(addr_size * 3)
		self.entry_point = tmp[:addr_size]
		self.entry_point[::-1]
		self.ph_off = tmp[addr_size:addr_size * 2]
		self.sh_off = tmp[addr_size * 2:]
		tmp = f.read(0xF)
		self.flags = tmp[:4]
		self.eh_size = tmp[4:6]
		self.phentsize = tmp[6:8]
		self.phnum = tmp[8:10]
		self.shentsize = tmp[10:12]
		self.shnum = tmp[12:14]
		self.shstrndx = tmp[14:16]
		if self.endianness == 1:
			self.entry_point = self.entry_point[::-1]
			self.ph_off = self.ph_off[::-1]
			self.sh_off = self.sh_off[::-1]
			self.type = self.type[::-1]
			self.inst_arch = self.inst_arch[::-1]
			self.eh_size = self.eh_size[::-1]
			self.phnum = self.phnum[::-1]
			self.phentsize = self.phentsize[::-1]
			self.shentsize = self.shentsize[::-1]
			self.shnum = self.shnum[::-1]
			self.shstrndx = self.shstrndx[::-1]
		self.ph_off = int.from_bytes(self.ph_off, 'big')
		self.sh_off = int.from_bytes(self.sh_off, 'big')
		self.eh_size = int.from_bytes(self.eh_size, 'big')
		self.phentsize = int.from_bytes(self.phentsize, 'big')
		self.phnum = int.from_bytes(self.phnum, 'big')
		self.shentsize = int.from_bytes(self.shentsize, 'big')
		self.shnum = int.from_bytes(self.shnum, 'big')
		self.shstrndx = int.from_bytes(self.shstrndx, 'big')
		self.sh_list = []
		for i in range(0, self.shnum):
			f.seek(self.sh_off + (self.shentsize * i))
			self.sh_list.append(sectionHeader(f.read(self.shentsize), self))
		for x in self.sh_list:
			x.setName(self, f)
		f.close()
		if self.process_parse() == -1:
			return(-1)
		self.parsed = 1

	def print(self):
		if self.parsed != 1:
			print(self.filename + " is not parsed yet")
			return
		print("Filename : " + self.filename)
		print("Instruction set size : " + str(self.bits) + " bits")
		print("Endianness : " + self.endianness)
		print("ABI : " + self.os_abi)
		print("Type : " + self.type)
		print("Instruction set : " + self.inst_arch)
		print("Entry point : 0x" + self.entry_point.hex())
		print("Program header offset : " + str(self.ph_off))
		print("Section header offset : " + str(self.sh_off))
		print("Flags : 0x" + self.flags.hex())
		print("ELF header size : " + str(self.eh_size))
		print("Program header number : " + str(self.phnum))
		print("Program header size : " + str(self.phentsize))
		print("Section header number : " + str(self.shnum))
		print("Section header size : " + str(self.shentsize))
		print("Section header index for str : " + str(self.shstrndx))
		print("Section headers :")
		tmp = 0
		for i in self.sh_list:
			print(str(tmp) + " " + "-" * 20)
			tmp += 1
			i.print()

	def __str__(self):
		if self.parsed == 0:
			return (self.filename + " is not parsed yet")
			return
		ret_str = ""
