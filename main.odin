package main

import "core:fmt"
import "core:os"

import "elf"

panic :: proc(fmt_in: string, args: ..any) {
	fmt.printf(fmt_in, ..args)
	os.exit(1)
}

main :: proc() {
	if len(os.args) < 2 {
		panic("Please provide elfo a program to parse\n")
	}

	binary_blob, ok := os.read_entire_file_from_filename(os.args[1])
	if !ok {
		panic("Failed to load file: %s\n", os.args[1])
	}

	info, sections, err := elf.load_elf(binary_blob)
	if err != nil {
		panic("Failed to load elf! %s\n", err)
	}
	fmt.printf("%#s\n", info)
	elf.print_sections_by_size(&sections)

	libraries := elf.load_dynamic_libraries(sections[".dynamic"].data, sections[".dynstr"].data)
	elf.print_dynamic_libraries(libraries)

	sym := elf.load_symbols(sections[".symtab"].data, sections[".strtab"].data)
	dynsym := elf.load_symbols(sections[".dynsym"].data, sections[".dynstr"].data)

/*
	fmt.printf("Non Dynamic Symbols:\n")
	print_symbols(sym)
	fmt.printf("    Dynamic Symbols:\n")
	print_symbols(dynsym)
*/
}
