package elf

import "core:fmt"
import "core:mem"
import "core:strings"
import "core:intrinsics"
import "core:slice"
import "core:runtime"

/*
Handy References:
- https://refspecs.linuxbase.org/elf/elf.pdf
- http://man7.org/linux/man-pages/man5/elf.5.html
*/

ELFCLASS32  :: 1
ELFCLASS64  :: 2
ELFDATA2LSB :: 1
ELFDATA2MSB :: 2

File_Type :: enum {
	none        = 0x0,
	relocatable = 0x1,
	executable  = 0x2,
	shared_obj  = 0x3,
	core        = 0x4,
	lo_os       = 0xFE00,
	hi_os       = 0xFEFF,
	lo_proc     = 0xFF00,
	hi_proc     = 0xFFFF,
}

Processor_Type :: enum {
	none              = 0x000,
	att_we_32100      = 0x001,
	sparc             = 0x002,
	x86               = 0x003,
	m68k              = 0x004,
	m88k              = 0x005,
	imcu              = 0x006,
	i80860            = 0x007,
	mips              = 0x008,
	system_370        = 0x009,
	mips_rs3000_le    = 0x00A,
	hp_pa_risc        = 0x00E,
	i80960            = 0x013,
	ppc               = 0x014,
	ppc_64            = 0x015,
	s390              = 0x016,
	ibm_spu           = 0x017,
	nec_v800          = 0x024,
	fujitsu_fr20      = 0x025,
	trw_rh32          = 0x026,
	motorola_rce      = 0x027,
	arm               = 0x028,
	alpha             = 0x029,
	super_h           = 0x02A,
	sparc_v9          = 0x02B,
	siemens_tricore   = 0x02C,
	argonaut_risc     = 0x02D,
	hitachi_h8_300    = 0x02E,
	hitachi_h8_300h   = 0x02F,
	hitachi_h8s       = 0x030,
	hitachi_h8_500    = 0x031,
	itanium           = 0x032,
	stanford_mips_x   = 0x033,
	motorola_coldfire = 0x034,
	motorola_m68hc12  = 0x035,
	fujitsu_mma       = 0x036,
	siemens_pcp       = 0x037,
	sony_ncpu_risc    = 0x038,
	denso_ndr1        = 0x039,
	motorola_starcore = 0x03A,
	toyota_me16       = 0x03B,
	stmicro_st100     = 0x03C,
	alc_tinyj         = 0x03D,
	x86_64            = 0x03E,
	tms320c6000       = 0x08C,
	mcst_elbrus_e2k   = 0x0AF,
	arm_64            = 0x0B7,
	risc_v            = 0x0F3,
	bpf               = 0x0F7,
	wdc_65c816        = 0x101,
}

Target_ABI :: enum {
	system_v       = 0x00,
	hp_ux          = 0x01,
	netbsd         = 0x02,
	linux          = 0x03,
	gnu_hurd       = 0x04,
	solaris        = 0x06,
	aix            = 0x07,
	irix           = 0x08,
	freebsd        = 0x09,
	tru64          = 0x0A,
	novell_modesto = 0x0B,
	openbsd        = 0x0C,
	openvms        = 0x0D,
	nonstop_kernel = 0x0E,
	aros           = 0x0F,
	fenix_os       = 0x10,
	cloud_abi      = 0x11,
	open_vos       = 0x12,
}

Section_Flags :: enum u64 {
	write      = 0x1,
	alloc      = 0x2,
	executable = 0x4,
	merge      = 0x10,
	strings    = 0x20,
	info_link  = 0x40,
	os_nonconforming = 0x100,
	group      = 0x200,
	tls        = 0x400,
	mask_os    = 0x0FF00000,
	mask_proc  = 0xF0000000,
	ordered    = 0x4000000,
	exclude    = 0x8000000,
}

Section_Header_Type :: enum {
	null     = 0x00,
	progbits = 0x01,
	symtab   = 0x02,
	strtab   = 0x03,
	rela     = 0x04,
	hash     = 0x05,
	dyn      = 0x06,
	note     = 0x07,
	nobits   = 0x08,
	rel      = 0x09,
	dynsym   = 0x0B,
	init_array  = 0x0E,
	fini_array  = 0x0F,
	gnu_hash    = 0x6FFFFFF6,
	gnu_verdef  = 0x6FFFFFFD,
	gnu_verneed = 0x6FFFFFFE,
	gnu_versym  = 0x6FFFFFFF,
	unwind      = 0x70000001,
}

Section_Type :: enum {
	null    = 0,
	load    = 1,
	dyn     = 2,
	interp  = 3,
	note    = 4,
	shlib   = 5,
	phdr    = 6,
	tls     = 7,
	gnu_eh_frame = 0x6474e550,
	gnu_stack    = 0x6474e551,
	gnu_relro    = 0x6474e552,
	gnu_property = 0x6474e553,
	lowproc      = 0x70000000,
	hiproc       = 0x7FFFFFFF,
}

Dynamic_Type :: enum {
	null         = 0,
	needed       = 1,
	plt_rel_size = 2,
	plt_got      = 3,
	hash         = 4,
	strtab       = 5,
	symtab       = 6,
	rela         = 7,
	rela_size    = 8,
	rela_entry   = 9,
	str_size     = 10,
	symbol_entry = 11,
	init         = 12,
	fini         = 13,
	so_name      = 14,
	rpath        = 15,
	symbolic     = 16,
	rel          = 17,
	rel_size     = 18,
	rel_entry    = 19,
	plt_rel      = 20,
	debug        = 21,
	text_rel     = 22,
	jump_rel     = 23,
	bind_now     = 24,
	init_array   = 25,
	init_array_size  = 26,
	fini_array       = 27,
	fini_array_size  = 28,
	gnu_hash         = 0x6FFFFEF5,
	version_symbol   = 0x6FFFFFF0,
	version_need     = 0x6FFFFFFE,
	version_need_num = 0x6FFFFFFF,
	lo_proc          = 0x70000000,
	hi_proc          = 0x7FFFFFFF,
}

Symbol_Binding :: enum u8 {
	local  = 0,
	global = 1,
	weak   = 2,
	loos   = 10,
	hios   = 12,
	loproc = 13,
	hiproc = 15,
}

Symbol_Type :: enum u8 {
	notype  = 0,
	object  = 1,
	func    = 2,
	section = 3,
	file    = 4,
	common  = 5,
	tls     = 6,
	loos    = 10,
	hios    = 12,
	loproc  = 13,
	hiproc  = 15,
}

ELF_Parse_Error :: enum {
	no_error = 0,
	invalid_magic,
	invalid_header_version,
	invalid_class,
	invalid_endianness,
	invalid_section_header_offset,
	invalid_string_table_header,
	invalid_section_offset,
	invalid_file,
}

Symbol :: struct {
	name: string,
	value: u64,
	size: u64,
	type: Symbol_Type,
	bind: Symbol_Binding,
}

ELF_Pre_Header :: struct #packed {
	magic: [4]u8,
	class: u8,
	endian: u8,
	hdr_version: u8,
	target_abi: u8,
	pad: [8]u8,
}

ELF32_Header :: struct #packed {
	ident: [16]u8,

	type: u16,
	machine: u16,
	version: u32,
	entry: u32,
	program_hdr_offset: u32,
	section_hdr_offset: u32,
	flags: u32,
	ehsize: u16,
	program_hdr_entry_size: u16,
	program_hdr_num: u16,
	section_entry_size: u16,
	section_hdr_num: u16,
	section_hdr_str_idx: u16,
}

ELF64_Header :: struct #packed {
	ident: [16]u8,

	type: u16,
	machine: u16,
	version: u32,
	entry: u64,
	program_hdr_offset: u64,
	section_hdr_offset: u64,
	flags: u32,
	ehsize: u16,
	program_hdr_entry_size: u16,
	program_hdr_num: u16,
	section_entry_size: u16,
	section_hdr_num: u16,
	section_hdr_str_idx: u16,
}

ELF_Header :: struct {
	program_hdr_offset: u64,
	section_hdr_offset: u64,
	program_hdr_num: u16,
	program_hdr_entry_size: u16,
	section_entry_size: u16,
	section_hdr_num: u16,
	section_hdr_str_idx: u16,
}

ELF32_Section_Header :: struct #packed {
	name: u32,
	type: u32,
	flags: u32,
	addr: u32,
	offset: u32,
	size: u32,
	link: u32,
	info: u32,
	addr_align: u32,
	entry_size: u32,
}

ELF64_Section_Header :: struct #packed {
	name: u32,
	type: u32,
	flags: u64,
	addr: u64,
	offset: u64,
	size: u64,
	link: u32,
	info: u32,
	addr_align: u64,
	entry_size: u64,
}

ELF_Section_Header :: struct {
	name: u32,
	type: Section_Header_Type,
	flags: u64,
	addr: u64,
	offset: u64,
	size: u64,
	link: u32,
	info: u32,
	addr_align: u64,
	entry_size: u64,
}

ELF32_Program_Header :: struct #packed {
	type: u32,
	offset: u32,
	virtual_addr: u32,
	physical_addr: u32,
	file_size: u32,
	mem_size: u32,
	flags: u32,
	align: u32,
}

ELF64_Program_Header :: struct #packed {
	type: u32,
	flags: u32,
	offset: u64,
	virtual_addr: u64,
	physical_addr: u64,
	file_size: u64,
	mem_size: u64,
	align: u64,
}

ELF_Program_Header :: struct {
	type: Section_Type,
	flags:         u32,
	offset:        u64,
	virtual_addr:  u64,
	physical_addr: u64,
	file_size:     u64,
	mem_size:      u64,
	align:         u64,
}

ELF32_Dyn :: struct #packed {
	tag: i32,
	val: u32,
}

ELF64_Dyn :: struct #packed {
	tag: i64,
	val: u64,
}

ELF_Dynamic :: struct {
	tag: i64,
	val: u64,
}

ELF32_Sym :: struct #packed {
	name:  u32,
	value: u32,
	size:  u32,
	info:  u8,
	other: u8,
	shndx: u16,
}

ELF64_Sym :: struct #packed {
	name:  u32,
	info:  u8,
	other: u8,
	shndx: u16,
	value: u64,
	size:  u64,
}

ELF_Symbol :: struct {
	name:  u32,
	info:  u8,
	other: u8,
	shndx: u16,
	value: u64,
	size:  u64,
}

ELF32_Rel :: struct #packed {
	offset: u32,
	info:   u32,
}

ELF32_Rela :: struct #packed {
	offset: u32,
	info:   u32,
	addend: i32,
}

ELF64_Rel :: struct #packed {
	offset: u64,
	info:   u64,
}

ELF64_Rela :: struct #packed {
	offset: u64,
	info:   u64,
	addend: i64,
}

Relocation :: struct {
	offset: u64,
	symbol: u32,
	type:   u32,
	addend: i64,
}

Section :: struct {
	name: string,
	type: Section_Header_Type,
	link: u32,

	flags: u64,
	data: []u8,
	file_offset: u64,
	virtual_addr: u64,
	addr_alignment: u64,

	children: []uint,
}

ELF_Context :: struct {
	little_endian: bool,
	bits_64: bool,
	target_abi: Target_ABI,
	file_type: File_Type,
	isa: Processor_Type,
	entrypoint: u64,
	linker_path: string,

	sections: []Section,
	section_map: map[string]uint,
}

slice_to_type :: proc(buf: []u8, $T: typeid) -> (T, bool) #optional_ok {
    if len(buf) < size_of(T) {
        return {}, false
    }
    return intrinsics.unaligned_load((^T)(raw_data(buf))), true
}

parse_common_header :: proc(ctx: ^ELF_Context, blob: []u8) -> (ELF_Header, int, bool) {
	iter_size := 0

	common_hdr := ELF_Header{}
	if ctx.bits_64 {
		hdr, ek := slice_to_type(blob, ELF64_Header)
		if !ek {
			return {}, 0, false
		}

		common_hdr.program_hdr_offset     = hdr.program_hdr_offset
		common_hdr.program_hdr_num        = hdr.program_hdr_num
		common_hdr.program_hdr_entry_size = hdr.program_hdr_entry_size
		common_hdr.section_hdr_offset     = hdr.section_hdr_offset
		common_hdr.section_hdr_str_idx    = hdr.section_hdr_str_idx
		common_hdr.section_hdr_num        = hdr.section_hdr_num
		common_hdr.section_entry_size     = hdr.section_entry_size

		ctx.isa        = Processor_Type(hdr.machine)
		ctx.file_type  = File_Type(hdr.type)
		ctx.entrypoint = hdr.entry

		iter_size = size_of(ELF64_Header)
	} else {
		hdr, ek := slice_to_type(blob, ELF32_Header)
		if !ek {
			return {}, 0, false
		}

		common_hdr.program_hdr_offset     = u64(hdr.program_hdr_offset)
		common_hdr.program_hdr_num        = hdr.program_hdr_num
		common_hdr.program_hdr_entry_size = hdr.program_hdr_entry_size
		common_hdr.section_hdr_offset     = u64(hdr.section_hdr_offset)
		common_hdr.section_hdr_str_idx    = hdr.section_hdr_str_idx
		common_hdr.section_hdr_num        = hdr.section_hdr_num
		common_hdr.section_entry_size     = hdr.section_entry_size

		ctx.isa        = Processor_Type(hdr.machine)
		ctx.file_type  = File_Type(hdr.type)
		ctx.entrypoint = u64(hdr.entry)

		iter_size = size_of(ELF32_Header)
	}

	return common_hdr, iter_size, true
}

parse_program_header :: proc(ctx: ^ELF_Context, blob: []u8) -> (ELF_Program_Header, int, bool) {
	iter_size := 0

	common_hdr := ELF_Program_Header{}
	if ctx.bits_64 {
		hdr, strk := slice_to_type(blob, ELF64_Program_Header)
		if !strk {
			return {}, 0, false
		}

		common_hdr.type          = Section_Type(hdr.type)
		common_hdr.flags         = hdr.flags
		common_hdr.offset        = hdr.offset
		common_hdr.virtual_addr  = hdr.virtual_addr
		common_hdr.physical_addr = hdr.physical_addr
		common_hdr.file_size     = hdr.file_size
		common_hdr.mem_size      = hdr.mem_size
		common_hdr.align         = hdr.align

		iter_size  = size_of(ELF64_Program_Header)
	} else {
		hdr, strk := slice_to_type(blob, ELF32_Program_Header)
		if !strk {
			return {}, 0, false
		}

		common_hdr.type          = Section_Type(hdr.type)
		common_hdr.flags         = hdr.flags
		common_hdr.offset        = u64(hdr.offset)
		common_hdr.virtual_addr  = u64(hdr.virtual_addr)
		common_hdr.physical_addr = u64(hdr.physical_addr)
		common_hdr.file_size     = u64(hdr.file_size)
		common_hdr.mem_size      = u64(hdr.mem_size)
		common_hdr.align         = u64(hdr.align)

		iter_size  = size_of(ELF32_Program_Header)
	}

	return common_hdr, iter_size, true
}

parse_section_header :: proc(ctx: ^ELF_Context, blob: []u8) -> (ELF_Section_Header, int, bool) {
	iter_size := 0

	cmn_hdr := ELF_Section_Header{}
	if ctx.bits_64 {
		hdr, strk := slice_to_type(blob, ELF64_Section_Header)
		if !strk {
			return {}, 0, false
		}

		cmn_hdr.name       = hdr.name
		cmn_hdr.type       = Section_Header_Type(hdr.type)
		cmn_hdr.flags      = hdr.flags
		cmn_hdr.addr       = hdr.addr
		cmn_hdr.offset     = hdr.offset
		cmn_hdr.size       = hdr.size
		cmn_hdr.link       = hdr.link
		cmn_hdr.info       = hdr.info
		cmn_hdr.addr_align = hdr.addr_align
		cmn_hdr.entry_size = hdr.entry_size

		iter_size = size_of(ELF64_Section_Header)
	} else {
		hdr, strk := slice_to_type(blob, ELF32_Section_Header)
		if !strk {
			return {}, 0, false
		}

		cmn_hdr.name       = hdr.name
		cmn_hdr.type       = Section_Header_Type(hdr.type)
		cmn_hdr.flags      = u64(hdr.flags)
		cmn_hdr.addr       = u64(hdr.addr)
		cmn_hdr.offset     = u64(hdr.offset)
		cmn_hdr.size       = u64(hdr.size)
		cmn_hdr.link       = hdr.link
		cmn_hdr.info       = hdr.info
		cmn_hdr.addr_align = u64(hdr.addr_align)
		cmn_hdr.entry_size = u64(hdr.entry_size)

		iter_size = size_of(ELF32_Section_Header)
	}

	return cmn_hdr, iter_size, true
}

parse_symbol :: proc(ctx: ^ELF_Context, blob: []u8) -> (ELF_Symbol, int, bool) {
	iter_size := 0

	cmn_sym := ELF_Symbol{}
	if ctx.bits_64 {
		sym, strk := slice_to_type(blob, ELF64_Sym)
		if !strk {
			return {}, 0, false
		}

		cmn_sym.name  = sym.name
		cmn_sym.info  = sym.info
		cmn_sym.other = sym.other
		cmn_sym.shndx = sym.shndx
		cmn_sym.value = sym.value
		cmn_sym.size  = sym.size

		iter_size = size_of(ELF64_Sym)
	} else {
		sym, strk := slice_to_type(blob, ELF32_Sym)
		if !strk {
			return {}, 0, false
		}

		cmn_sym.name = sym.name
		cmn_sym.info = sym.info
		cmn_sym.other = sym.other
		cmn_sym.shndx = sym.shndx
		cmn_sym.value = u64(sym.value)
		cmn_sym.size  = u64(sym.size)

		iter_size = size_of(ELF32_Sym)
	}

	return cmn_sym, iter_size, true

}

parse_dynamic :: proc(ctx: ^ELF_Context, blob: []u8) -> (ELF_Dynamic, int, bool) {
	iter_size := 0

	cmn_dyn := ELF_Dynamic{}
	if ctx.bits_64 {
		dyn, ok := slice_to_type(blob, ELF64_Dyn)
		if !ok {
			return {}, 0, false
		}

		cmn_dyn.tag = dyn.tag
		cmn_dyn.val = dyn.val

		iter_size = size_of(ELF64_Dyn)
	} else {
		dyn, ok := slice_to_type(blob, ELF32_Dyn)
		if !ok {
			return {}, 0, false
		}

		cmn_dyn.tag = i64(dyn.tag)
		cmn_dyn.val = u64(dyn.val)

		iter_size = size_of(ELF32_Dyn)
	}

	return cmn_dyn, iter_size, true

}

parse_reloc :: proc(ctx: ^ELF_Context, blob: []u8, has_addend: bool) -> (Relocation, int, bool) {
	iter_size := 0

	r := Relocation{}
	if ctx.bits_64 {
		if has_addend {
			reloc, ok := slice_to_type(blob, ELF64_Rela)
			if !ok {
				return {}, 0, false
			}

			r.offset = reloc.offset
			r.symbol = u32(reloc.info >> 32)
			r.type   = u32(reloc.info & 0xFFFFFFFF)
			r.addend = reloc.addend
			iter_size = size_of(ELF64_Rela)
		} else {
			reloc, ok := slice_to_type(blob, ELF64_Rel)
			if !ok {
				return {}, 0, false
			}

			r.offset = reloc.offset
			r.symbol = u32(reloc.info >> 32)
			r.type   = u32(reloc.info & 0xFFFFFFFF)
			iter_size = size_of(ELF64_Rel)
		}
	} else {
		if has_addend {
			reloc, ok := slice_to_type(blob, ELF32_Rela)
			if !ok {
				return {}, 0, false
			}

			r.offset = u64(reloc.offset)
			r.symbol = u32(reloc.info >> 8)
			r.type   = u32(u8(reloc.info))
			r.addend = i64(reloc.addend)
			iter_size = size_of(ELF32_Rela)
		} else {
			reloc, ok := slice_to_type(blob, ELF32_Rel)
			if !ok {
				return {}, 0, false
			}

			r.offset = u64(reloc.offset)
			r.symbol = u32(reloc.info >> 8)
			r.type   = u32(u8(reloc.info))
			iter_size = size_of(ELF32_Rel)
		}
	}

	return r, iter_size, true

}

load_elf :: proc(binary_blob: []u8, allocator := context.allocator) -> (elf_ctx: ELF_Context, err: ELF_Parse_Error) {
	context.allocator = allocator

	pre_hdr, rk := slice_to_type(binary_blob, ELF_Pre_Header)
	if !rk {
		err = .invalid_file
		return
	}

	elf_magic := []u8{ 0x7f, 'E', 'L', 'F' }
	if mem.compare(pre_hdr.magic[:], elf_magic) != 0 {
		err = .invalid_magic
		return
	}

	if pre_hdr.hdr_version != 1 {
		err = .invalid_header_version
		return
	}

	ctx := ELF_Context{}
	if pre_hdr.class == ELFCLASS64 {
		ctx.bits_64 = true;
	} else if pre_hdr.class == ELFCLASS32 {
		ctx.bits_64 = false;
	} else {
		err = .invalid_class
		return
	}

	if pre_hdr.endian == ELFDATA2LSB {
		ctx.little_endian = true;
	} else if pre_hdr.endian == ELFDATA2MSB {
		ctx.little_endian = false;
	} else {
		err = .invalid_endianness
		return
	}
	ctx.target_abi = Target_ABI(pre_hdr.target_abi)

	common_hdr, _, ok := parse_common_header(&ctx, binary_blob)
	if !ok {
		err = .invalid_file
		return
	}

	if common_hdr.section_hdr_offset > u64(len(binary_blob)) {
		err = .invalid_section_header_offset
		return
	}

	program_header_array_size := int(common_hdr.program_hdr_num) * int(common_hdr.program_hdr_entry_size)
	program_header_blob := binary_blob[int(common_hdr.program_hdr_offset):int(common_hdr.program_hdr_offset)+program_header_array_size]
	for i := 0; i < program_header_array_size; i += int(common_hdr.program_hdr_entry_size) {
		prog_hdr, _, pok := parse_program_header(&ctx, program_header_blob[i:])
		if !pok {
			err = .invalid_file
			return
		}

		if prog_hdr.type != Section_Type.interp {
			continue
		}

		linker_path := binary_blob[prog_hdr.offset:prog_hdr.offset+prog_hdr.mem_size]
		ctx.linker_path = strings.clone_from_cstring(cstring(raw_data(linker_path)))
		break
	}

	str_table_hdr_idx := common_hdr.section_hdr_offset + u64(common_hdr.section_hdr_str_idx * common_hdr.section_entry_size)
	if str_table_hdr_idx > u64(len(binary_blob)) {
		err = .invalid_string_table_header
		return
	}

	str_table_hdr, _, strk := parse_section_header(&ctx, binary_blob[str_table_hdr_idx:])
	if !strk {
		err = .invalid_file
		return
	}

	if str_table_hdr.type != Section_Header_Type.strtab {
		err = .invalid_string_table_header
		return
	}

	if str_table_hdr.offset > u64(len(binary_blob)) {
		err = .invalid_file
		return
	}

	section_header_array_size := int(common_hdr.section_hdr_num) * int(common_hdr.section_entry_size)
	section_header_blob := binary_blob[int(common_hdr.section_hdr_offset):int(common_hdr.section_hdr_offset)+section_header_array_size]

	_sections := make([dynamic]Section)
	_section_map := make(map[string]uint)
	for i := 0; i < section_header_array_size; i += int(common_hdr.section_entry_size) {
		section_hdr, _, sk := parse_section_header(&ctx, section_header_blob[i:])
		if !sk {
			delete(_sections)
			free_sections(_section_map)
			err = .invalid_file
			return
		}

		if section_hdr.offset > u64(len(binary_blob)) {
			delete(_sections)
			free_sections(_section_map)
			err = .invalid_section_offset
			return
		}

		section_name_blob := binary_blob[str_table_hdr.offset + u64(section_hdr.name):]
		section_name := ""
		if section_name_blob[0] != 0 {
			section_name = strings.clone_from_cstring(cstring(raw_data(section_name_blob)))
		}

		s := Section{
			name = section_name,
			type = section_hdr.type,
			link = section_hdr.link,
			flags = section_hdr.flags,
			file_offset = section_hdr.offset,
			addr_alignment = section_hdr.addr_align,
			virtual_addr = section_hdr.addr,
		}

		if section_hdr.type == .nobits || section_hdr.type == .null {
			s.data = nil
		} else {
			s.data = mem.clone_slice(binary_blob[section_hdr.offset:section_hdr.offset+section_hdr.size])
		}

		s_idx := len(_sections)
		append(&_sections, s)
		_section_map[section_name] = uint(s_idx)
	}

	ctx.sections = _sections[:]
	ctx.section_map = _section_map
	return ctx, nil
}

free_sections :: proc(sections: map[string]uint) {
	for k, v in sections {
		delete(k)
	}

	delete(sections)
}

load_symbols :: proc(ctx: ^ELF_Context, name: string, strtab: string, allocator := context.allocator) -> ([]Symbol, bool) {
	context.allocator = allocator

	if !(name in ctx.section_map) || !(strtab in ctx.section_map) {
		return nil, false
	}

	sym_section := ctx.sections[ctx.section_map[name]].data
	str_section := ctx.sections[ctx.section_map[strtab]].data

	symbols := make([dynamic]Symbol)
	for i := 0; i < len(sym_section); {
		sym_entry, iter_size, ok := parse_symbol(ctx, sym_section[i:])
		if !ok {
			free_symbols(symbols[:])
			return nil, false
		}

		bind := Symbol_Binding(u8(sym_entry.info >> 4))
		type := Symbol_Type(u8(sym_entry.info & 0xf))

		sym_name := strings.clone_from_cstring(cstring(raw_data(str_section[sym_entry.name:])))
		s := Symbol{value = sym_entry.value, size = sym_entry.size, bind = bind, type = type, name = sym_name}

		append(&symbols, s)
		i += iter_size
	}

	return symbols[:], true
}

free_symbols :: proc(symbols: []Symbol) {
	for i := 0; i < len(symbols); i += 1 {
		delete(symbols[i].name)
	}

	delete(symbols)
}

load_dynamic_libraries :: proc(ctx: ^ELF_Context, name: string, strtab: string, allocator := context.allocator) -> ([]string, bool) {
	context.allocator = allocator

	if !(name in ctx.section_map) || !(strtab in ctx.section_map) {
		return nil, false
	}

	dyn_section := ctx.sections[ctx.section_map[name]].data
	str_section := ctx.sections[ctx.section_map[strtab]].data

	libraries := make([dynamic]string)
	for i := 0; i < len(dyn_section); {
		dyn_entry, iter_size, ok := parse_dynamic(ctx, dyn_section[i:])
		if !ok {
			free_dynamic_libraries(libraries[:])
			return nil, false
		}

		if Dynamic_Type(dyn_entry.tag) == Dynamic_Type.needed {
			section_name := cstring(raw_data(str_section[dyn_entry.val:]))
			append(&libraries, strings.clone_from_cstring(section_name))
		}

		i += iter_size
	}

	return libraries[:], true
}

load_relocations :: proc(ctx: ^ELF_Context, name: string, allocator := context.allocator) -> ([]Relocation, bool) {
	context.allocator = allocator

	if !(name in ctx.section_map) {
		return nil, false
	}

	reloc_section := ctx.sections[ctx.section_map[name]]
	reloc_bytes := reloc_section.data

	if reloc_section.type != .rela && reloc_section.type != .rel {
		return nil, false
	}

	relocations := make([dynamic]Relocation)
	for i := 0; i < len(reloc_bytes); {
		reloc, iter_size, ok := parse_reloc(ctx, reloc_bytes[i:], reloc_section.type == .rela)
		if !ok {
			delete(relocations)
			return nil, false
		}

		append(&relocations, reloc)
		i += iter_size
	}

	return relocations[:], true
}

free_dynamic_libraries :: proc(libraries: []string) {
	for i := 0; i < len(libraries); i += 1 {
		delete(libraries[i])
	}

	delete(libraries)
}

print_sections_by_size :: proc(ctx: ^ELF_Context, temp_allocator := context.temp_allocator) {
	context.temp_allocator = temp_allocator
	sections := mem.clone_slice(ctx.sections, context.temp_allocator)

	slice.sort_by(sections, proc(a: Section, b: Section) -> bool { return len(a.data) < len(b.data) })
	for v in sections {
		kb_size := len(v.data) / 1024
		mb_size := len(v.data) / (1024 * 1024)

		str_buf := [4096]u8{}
		b := strings.builder_from_slice(str_buf[:])

		if mb_size > 0 {
			fmt.sbprintf(&b, "%d MB", mb_size)
		} else if kb_size > 0 {
			fmt.sbprintf(&b, "%d KB", kb_size)
		} else {
			fmt.sbprintf(&b, "%d  B", len(v.data))
		}

		fmt.printf("%022s %07s\n", v.name, strings.to_string(b))
	}
}

print_symbols :: proc(symbols: []Symbol) {
	for symbol in symbols {
		fmt.printf("0x%08x - %06d B | %06s %07s | %s\n", symbol.value, symbol.size, symbol.bind, symbol.type, symbol.name)
	}
}

print_relocations :: proc(ctx: ^ELF_Context, relocations: []Relocation) {
	for reloc in relocations {
		fmt.printf("0x%x 0x%x 0x%x + %d\n", reloc.offset, reloc.type, reloc.symbol, reloc.addend)
	}
}

print_dynamic_libraries :: proc(libraries: []string) {
	for i := 0; i < len(libraries); i += 1 {
		fmt.printf("NEEDED %s\n", libraries[i])
	}
}
