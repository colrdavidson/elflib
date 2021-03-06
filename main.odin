package main

import "core:fmt"
import "core:os"
import "core:time"

import "elf"

panic :: proc(fmt_in: string, args: ..any) {
	fmt.printf(fmt_in, ..args)
	os.exit(1)
}

_main :: proc() {
	if len(os.args) < 2 {
		panic("Please provide elfo a program to parse\n")
	}

	read_start := time.tick_now()
	binary_blob, ok := os.read_entire_file_from_filename(os.args[1])
	if !ok {
		panic("Failed to load file: %s\n", os.args[1])
	}
	read_end := time.tick_now()
	fmt.printf("read time: %s\n", fmt.tprint(time.tick_diff(read_start, read_end)))

	parse_start := time.tick_now()
	ctx, err := elf.load_elf(binary_blob)
	if err != nil {
		panic("Failed to load elf! %s\n", err)
	}

	libraries, _ := elf.load_dynamic_libraries(&ctx, ".dynamic", ".dynstr")
	sym, _ := elf.load_symbols(&ctx, ".symtab", ".strtab")
	dynsym, _ := elf.load_symbols(&ctx, ".dynsym", ".dynstr")
	relocations, _ := elf.load_relocations(&ctx, ".rela.dyn")

	parse_end := time.tick_now()
	fmt.printf("parse time: %s\n", fmt.tprint(time.tick_diff(parse_start, parse_end)))
	fmt.printf("Got %d libaries\n", len(libraries))
	fmt.printf("Got %d symbols\n", len(sym) + len(dynsym))
	fmt.printf("Got %d relocations\n", len(relocations))
}

main :: proc() {
	if len(os.args) < 2 {
		panic("Please provide elfo a program to parse\n")
	}

	binary_blob, ok := os.read_entire_file_from_filename(os.args[1])
	if !ok {
		panic("Failed to load file: %s\n", os.args[1])
	}

	ctx, err := elf.load_elf(binary_blob)
	if err != nil {
		panic("Failed to load elf! %s\n", err)
	}

	fmt.printf("file type: %s\n", ctx.file_type)
	fmt.printf("isa: %s\n", ctx.isa)
	fmt.printf("abi: %s\n", ctx.target_abi)
	fmt.printf("endianness: %s\n", (ctx.little_endian ? "little" : "big"))
	fmt.printf("arch: %s\n", (ctx.bits_64 ? "64 bit" : "32 bit"))
	fmt.printf("entrypoint: 0x%x\n", ctx.entrypoint)
	elf.print_sections_by_size(&ctx)

	libraries, ok2 := elf.load_dynamic_libraries(&ctx, ".dynamic", ".dynstr")
	if !ok2 {
		panic("Failed to load dynamic libs!\n")
	}
	elf.print_dynamic_libraries(libraries)

	sym, ok3 := elf.load_symbols(&ctx, ".symtab", ".strtab")
	if ok3 {
		fmt.printf("Non Dynamic Symbols:\n")
		elf.print_symbols(sym)
	}

	dynsym, ok4 := elf.load_symbols(&ctx, ".dynsym", ".dynstr")
	if ok4 {
		fmt.printf("    Dynamic Symbols:\n")
		elf.print_symbols(dynsym)
	}

	relocations, ok5 := elf.load_relocations(&ctx, ".rel.dyn")
	if ok5 {
		fmt.printf(".text relocations\n")
		elf.print_relocations(&ctx, relocations)
	}
}
