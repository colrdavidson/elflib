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
	none           = 0x000,
	att_we_32100   = 0x001,
	sparc          = 0x002,
	x86            = 0x003,
	m68k           = 0x004,
	m88k           = 0x005,
	imcu           = 0x006,
	i80860         = 0x007,
	mips           = 0x008,
	system_370     = 0x009,
	mips_rs3000_le = 0x00A,
	hp_pa_risc     = 0x00E,
	i80960         = 0x013,
	ppc            = 0x014,
	ppc_64         = 0x015,
	s390           = 0x016,
	ibm_spu        = 0x017,
	nec_v800       = 0x024,
	fujitsu_fr20   = 0x025,
	trw_rh32       = 0x026,
	motorola_rce   = 0x027,
	arm            = 0x028,
	alpha          = 0x029,
	super_h        = 0x02A,
	sparc_v9       = 0x02B,
	siemens_tricore = 0x02C,
	argonaut_risc   = 0x02D,
	hitachi_h8_300  = 0x02E,
	hitachi_h8_300h = 0x02F,
	hitachi_h8s     = 0x030,
	hitachi_h8_500  = 0x031,
	itanium         = 0x032,
	stanford_mips_x  = 0x033,
	motorola_coldfire = 0x034,
	motorola_m68hc12 = 0x035,
	fujitsu_mma      = 0x036,
	siemens_pcp      = 0x037,
	sony_ncpu_risc   = 0x038,
	denso_ndr1       = 0x039,
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

Section_Header_Type :: enum u32 {
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
}

Section_Type :: enum u32 {
	null    = 0,
	load    = 1,
	dyn     = 2,
	interp  = 3,
	note    = 4,
	shlib   = 5,
	phdr    = 6,
	tls     = 7,
	gnu_eh_frame = 0x6474e550,
	gnu_stack = 0x6474e551,
	gnu_relro = 0x6474e552,
	gnu_property = 0x6474e553,
	lowproc = 0x70000000,
	hiproc  = 0x7FFFFFFF,
}

Dynamic_Type :: enum u64 {
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

ELF64_Header :: struct #packed {
	magic: [4]u8,
	class: u8,
	endian: u8,
	hdr_version: u8,
	target_abi: u8,
	pad: [8]u8,

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

ELF32_Header :: struct #packed {
	magic: [4]u8,
	class: u8,
	endian: u8,
	hdr_version: u8,
	target_abi: u8,
	pad: [8]u8,

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

ELF64_Section_Header :: struct #packed {
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

ELF64_Program_Header :: struct #packed {
	type: Section_Type,
	flags: u32,
	offset: u64,
	virtual_addr: u64,
	physical_addr: u64,
	file_size: u64,
	mem_size: u64,
	align: u64,
}

ELF64_Dyn :: struct #packed {
	tag: Dynamic_Type,
	val: u64,
}

ELF64_Sym :: struct #packed {
	name:  u32,
	info:  u8,
	other: u8,
	shndx: u16,
	value: u64,
	size:  u64,
}

ELF_Info :: struct {
	little_endian: bool,
	bits_64: bool,
	target_abi: Target_ABI,
	file_type: File_Type,
	isa: Processor_Type,
	entrypoint: u64,
}

Section :: struct {
	name: string,
	type: Section_Header_Type,
	flags: u64,
	data: []u8,
	file_offset: u64,
	virtual_addr: u64,
	addr_alignment: u64,
}

slice_to_type :: proc(buf: []u8, $T: typeid) -> (T, bool) #optional_ok {
    if len(buf) < size_of(T) {
        return {}, false
    }
    return intrinsics.unaligned_load((^T)(raw_data(buf))), true
}

load_elf :: proc(binary_blob: []u8) -> (info: ELF_Info, sections: map[string]Section, err: ELF_Parse_Error) {
	elf_hdr, rk := slice_to_type(binary_blob, ELF64_Header)
	if !rk {
		err = .invalid_file
		return
	}

	elf_magic := []u8{ 0x7f, 'E', 'L', 'F' }
	if mem.compare(elf_hdr.magic[:], elf_magic) != 0 {
		err = .invalid_magic
		return
	}

	if elf_hdr.hdr_version != 1 {
		err = .invalid_header_version
		return
	}

	info = ELF_Info{}
	if elf_hdr.class == ELFCLASS64 {
		info.bits_64 = true;
	} else if elf_hdr.class == ELFCLASS32 {
		info.bits_64 = false;
		fmt.panicf("Can't ELF32!\n")
	} else {
		err = .invalid_class
		return
	}

	if elf_hdr.endian == ELFDATA2LSB {
		info.little_endian = true;
	} else if elf_hdr.endian == ELFDATA2MSB {
		info.little_endian = false;
	} else {
		err = .invalid_endianness
		return
	}
	info.isa = Processor_Type(elf_hdr.machine)
	info.file_type = File_Type(elf_hdr.type)
	info.target_abi = Target_ABI(elf_hdr.target_abi)
	info.entrypoint = elf_hdr.entry

	if elf_hdr.section_hdr_offset > u64(len(binary_blob)) {
		err = .invalid_section_header_offset
		return
	}

	program_header_array_size := int(elf_hdr.program_hdr_num) * int(elf_hdr.program_hdr_entry_size)
	program_header_blob := binary_blob[int(elf_hdr.program_hdr_offset):int(elf_hdr.program_hdr_offset)+program_header_array_size]
	for i := 0; i < program_header_array_size; i += int(elf_hdr.program_hdr_entry_size) {
		prog_hdr, pok := slice_to_type(program_header_blob[i:], ELF64_Program_Header)
		if !pok {
			err = .invalid_file
			return
		}

		if prog_hdr.type == Section_Type.interp {
			linker_path := binary_blob[prog_hdr.offset:prog_hdr.offset+prog_hdr.mem_size]
			fmt.printf("Using dynamic linker: %s\n", cstring(raw_data(linker_path)))
		}
	}

	str_table_hdr_idx := elf_hdr.section_hdr_offset + u64(elf_hdr.section_hdr_str_idx * elf_hdr.section_entry_size)
	if str_table_hdr_idx > u64(len(binary_blob)) {
		err = .invalid_string_table_header
		return
	}

	str_table_hdr, strk := slice_to_type(binary_blob[str_table_hdr_idx:], ELF64_Section_Header)
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

	section_header_array_size := int(elf_hdr.section_hdr_num) * int(elf_hdr.section_entry_size)
	section_header_blob := binary_blob[int(elf_hdr.section_hdr_offset):int(elf_hdr.section_hdr_offset)+section_header_array_size]
	_sections := make(map[string]Section)
	for i := 0; i < section_header_array_size; i += int(elf_hdr.section_entry_size) {
		section_hdr, sk := slice_to_type(section_header_blob[i:], ELF64_Section_Header)
		if !sk {

			free_sections(_sections)
			err = .invalid_file
			return
		}

		if section_hdr.offset > u64(len(binary_blob)) {
			free_sections(_sections)
			err = .invalid_section_offset
			return
		}

		section_name_blob := binary_blob[str_table_hdr.offset + u64(section_hdr.name):]
		if section_name_blob[0] == 0 {
			continue
		}

		section_name := strings.clone_from_cstring(cstring(raw_data(section_name_blob)))
		s := Section{
			name = section_name,
			type = section_hdr.type,
			flags = section_hdr.flags,
			file_offset = section_hdr.offset,
			addr_alignment = section_hdr.addr_align,
			virtual_addr = section_hdr.addr,
		}

		if section_hdr.type == .nobits || section_hdr.type == .null {
			s.data = nil
		} else {
			s.data = binary_blob[section_hdr.offset:section_hdr.offset+section_hdr.size]
		}

		_sections[section_name] = s
	}


	return info, _sections, nil
}

free_sections :: proc(sections: map[string]Section) {
	for k, v in sections {
		delete(k)
	}

	delete(sections)
}

load_symbols :: proc(sym_section: []u8, str_section: []u8) -> []Symbol {
	symbols := make([dynamic]Symbol)
	for i := 0; i < len(sym_section); i += size_of(ELF64_Sym) {
		sym_entry, ok := slice_to_type(sym_section[i:], ELF64_Sym)
		if !ok {
			fmt.panicf("Unable to read ELF symbol tag\n")
		}

		bind := Symbol_Binding(u8(sym_entry.info >> 4))
		type := Symbol_Type(u8(sym_entry.info & 0xf))

		sym_name := strings.clone_from_cstring(cstring(raw_data(str_section[sym_entry.name:])))
		s := Symbol{value = sym_entry.value, size = sym_entry.size, bind = bind, type = type, name = sym_name}

		append(&symbols, s)
	}

	return symbols[:]
}

free_symbols :: proc(symbols: []Symbol) {
	for i := 0; i < len(symbols); i += 1 {
		delete(symbols[i].name)
	}

	delete(symbols)
}

load_dynamic_libraries :: proc(dyn_section: []u8, str_section: []u8) -> []string {

	libraries := make([dynamic]string)
	for i := 0; i < len(dyn_section); i += size_of(ELF64_Dyn) {
		dyn_entry, ok := slice_to_type(dyn_section[i:], ELF64_Dyn)
		if !ok {
			fmt.panicf("Unable to read ELF dynamic tag\n")
		}

		if dyn_entry.tag == Dynamic_Type.needed {
			section_name := cstring(raw_data(str_section[dyn_entry.val:]))
			append(&libraries, strings.clone_from_cstring(section_name))
		}
	}

	return libraries[:]
}

free_dynamic_libraries :: proc(libraries: []string) {
	for i := 0; i < len(libraries); i += 1 {
		delete(libraries[i])
	}

	delete(libraries)
}

sort_entries_by_length :: proc(m: ^$M/map[$K]$V, loc := #caller_location) {
	Entry :: struct {
		hash:  uintptr,
		next:  int,
		key:   K,
		value: V,
	}

	header := runtime.__get_map_header(m)
	entries := (^[dynamic]Entry)(&header.m.entries)
	slice.sort_by(entries[:], proc(a: Entry, b: Entry) -> bool { return len(a.value.data) < len(b.value.data) })
	runtime.__dynamic_map_reset_entries(header, loc)
}


print_sections_by_size :: proc(sections: ^map[string]Section) {
	sort_entries_by_length(sections)
	for k, v in sections {
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

		fmt.printf("%022s %07s\n", k, strings.to_string(b))
	}
}

print_symbols :: proc(symbols: []Symbol) {
	for symbol in symbols {
		fmt.printf("0x%08x - %06d B | %06s %07s | %s\n", symbol.value, symbol.size, symbol.bind, symbol.type, symbol.name)
	}
}

print_dynamic_libraries :: proc(libraries: []string) {
	for i := 0; i < len(libraries); i += 1 {
		fmt.printf("NEEDED %s\n", libraries[i])
	}
}
