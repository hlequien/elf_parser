import sys
import os

class elfInfo():
	"""elfInfo is designed to parse and store informations about an ELF file"""
	def __init__(self, file):
		self.filename = os.path.basename(file)
		self.file = file
		self.parsed = 0

	def gen_abi_dict(self):
		abi_dict = {b'\x00': "System V", b'\x01': "HP-UX", b'\x02': "NetBSD",
		b'\x03': "Linux", b'\x06': "Solaris", b'\x07': "AIX", b'\x08': "IRIX",
		b'\x09': "FreeBSD", b'\x0a': "Tru64", b'\x0b': "Novell Modesto",
		b'\x0c': "OpenBSD", b'\x0d': "OpenVMS", b'\x0e': "NonStop Kernel",
		b'\x0f': "AROS", b'\x10': "Fenix OS", b'\x11': "CloudABI", b'\x53': "Sortix"}
		return(abi_dict)

	def gen_type_dict(self):
		type_dict = {b'\x01\x00': "relocatable object", b'\x02\x00': "executable", b'\x03\x00': "shared object",
		b'\x04\x00': "core"}
		return(type_dict)

	def gen_arch_dict(self):
		arch_dict = {b'\x00\x00': "unspecified", b'\x02\x00': "SPARC", b'\x03\x00': "x86",
		b'\x08\x00': "MIPS", b'\x14\x00': "PowerPC", b'\x28\x00': "ARM", b'\x2a\x00': "SuperH",
		b'\x32\x00': "IA-64", b'\x3e\x00': "x86-64", b'\xb7\x00': "AArch64", b'\xf3\x00': "RISC-V"}
		return(arch_dict)

	def process_parse(self):
		if self.magic_nb != b'\x7fELF':
			print("elfInfo: " + self.filename + ": Not an ELF", file=sys.stderr)
			return(-1)
		self.magic_nb = "ELF"
		if self.bits == b'\x01':
			self.bits = 32
		elif self.bits == b'\x02':
			self.bits = 64
		else:
			self.bits = "unkown"
		if self.endianness == b'\x01':
			self.endianness = "little endian"
		elif self.endianness == b'\x02':
			self.endianness = "big endian"
		else:
			self.endianness = "unknown"
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
		self.magic_nb = f.read(4)
		self.bits = f.read(1)
		self.endianness = f.read(1)
		self.orig = f.read(1)
		self.os_abi = f.read(1)
		f.read(8)
		self.type = f.read(2)
		self.inst_arch = f.read(2)

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

	def __str__(self):
		if self.parsed == 0:
			return (self.filename + " is not parsed yet")
			return
		ret_str = ""
