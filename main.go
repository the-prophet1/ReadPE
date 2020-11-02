package main

import (
	"debug/pe"
	"fmt"
	"os"
)

func createMachineMap() map[uint16]string {
	return map[uint16]string{
		pe.IMAGE_FILE_MACHINE_UNKNOWN:   "未知CPU型号",
		pe.IMAGE_FILE_MACHINE_AM33:      "TAM33BD系列处理器",
		pe.IMAGE_FILE_MACHINE_AMD64:     "AMD64系列处理器",
		pe.IMAGE_FILE_MACHINE_ARM:       "ARM系列处理器",
		pe.IMAGE_FILE_MACHINE_ARM64:     "ARM64小端字节序系列处理器",
		pe.IMAGE_FILE_MACHINE_EBC:       "EFI Byte Code系列处理器",
		pe.IMAGE_FILE_MACHINE_I386:      "80386系列处理器",
		pe.IMAGE_FILE_MACHINE_IA64:      "Intel 64系列处理器",
		pe.IMAGE_FILE_MACHINE_M32R:      "M32R小端字节序系列处理器",
		pe.IMAGE_FILE_MACHINE_MIPS16:    "MIPS系列处理器",
		pe.IMAGE_FILE_MACHINE_MIPSFPU:   "MIPS系列处理器",
		pe.IMAGE_FILE_MACHINE_MIPSFPU16: "MIPS系列处理器",
		pe.IMAGE_FILE_MACHINE_POWERPC:   "IBM PowerPC小端字节序系列处理器",
		pe.IMAGE_FILE_MACHINE_POWERPCFP: "POWERPCFP系列处理器",
		pe.IMAGE_FILE_MACHINE_R4000:     "MIPS小端字节序系列处理器",
		pe.IMAGE_FILE_MACHINE_SH3:       "SH3小端字节序系列处理器",
		pe.IMAGE_FILE_MACHINE_SH3DSP:    "SH3DSP系列处理器",
		pe.IMAGE_FILE_MACHINE_SH4:       "SH4小端字节序系列处理器",
		pe.IMAGE_FILE_MACHINE_SH5:       "SH5小端字节序系列处理器",
		pe.IMAGE_FILE_MACHINE_THUMB:     "ARM Thumb/Thumb-2小端字节序系列处理器",
		pe.IMAGE_FILE_MACHINE_WCEMIPSV2: "MIPS 小端字节序 WCE v2系列处理器",
	}
}

func createDataDirectoryMap() map[uint16]string {
	return map[uint16]string{
		IMAGE_DIRECTORY_ENTRY_EXPORT:         "export table(导出表)",
		IMAGE_DIRECTORY_ENTRY_IMPORT:         "import table(导入表)",
		IMAGE_DIRECTORY_ENTRY_RESOURCE:       "resource table(资源表)",
		IMAGE_DIRECTORY_ENTRY_EXCEPTION:      "exception table",
		IMAGE_DIRECTORY_ENTRY_SECURITY:       "security table",
		IMAGE_DIRECTORY_ENTRY_BASERELOC:      "base location table（重定位表）",
		IMAGE_DIRECTORY_ENTRY_DEBUG:          "debug table",
		IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:   "architecture table",
		IMAGE_DIRECTORY_ENTRY_GLOBALPTR:      "global point table",
		IMAGE_DIRECTORY_ENTRY_TLS:            "tls table",
		IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:    "load config table",
		IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:   "bound import table",
		IMAGE_DIRECTORY_ENTRY_IAT:            "IAT table",
		IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:   "delay import table",
		IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: "com descriptor table",
	}
}

func init() {
	MachineMap = createMachineMap()
	DataDirectory = createDataDirectoryMap()
}

func printMachine(machine uint16) {
	description, flag := MachineMap[machine]
	if flag == false {
		fmt.Println("所属处理器平台:", "未知")
	} else {
		fmt.Println("所属处理器平台:", description)
	}
}

func printSections(number uint16) {
	fmt.Println("section数量:", number)
}

func printTimeDateStamp(time uint32) {
	fmt.Println("创建时间戳:", TimestampToDatetime(int64(time)))
}

func printPointerToSymbolTable(p *pe.FileHeader) {
	if p.PointerToSymbolTable == 0 {
		fmt.Println("符号表入口地址: 无符号表")
		fmt.Println("符号表符号个数: 无")
	} else {
		fmt.Printf("符号表入口地址: 0x%X\n", p.PointerToSymbolTable)
		fmt.Println("符号表符号个数:", p.NumberOfSymbols)
	}
}

func printCharacteristics(c uint16) {
	fmt.Println("PE文件特征:")
	var index = 1
	if c&uint16(IMAGE_FILE_RELOCS_STRIPPED) != 0 {
		fmt.Printf("    %d.重定位信息已从文件中删除,该文件必须以其首选的基地址加载,如果基址不可用,则加载程序报告错误\n", index)
		index++
	}
	if c&uint16(IMAGE_FILE_EXECUTABLE_IMAGE) != 0 {
		fmt.Printf("    %d.该文件是可执行文件\n", index)
		index++
	}
	if c&uint16(IMAGE_FILE_LINE_NUMS_STRIPPED) != 0 {
		fmt.Printf("    %d.COFF行号已从文件中删除\n", index)
		index++
	}
	if c&uint16(IMAGE_FILE_LOCAL_SYMS_STRIPPED) != 0 {
		fmt.Printf("    %d.COFF符号表条目已从文件中删除\n", index)
		index++
	}
	if c&uint16(IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0 {
		fmt.Printf("    %d.该应用程序可以处理大于2GB的地址\n", index)
		index++
	}
	if c&uint16(IMAGE_FILE_32BIT_MACHINE) != 0 {
		fmt.Printf("    %d.该计算机支持32位\n", index)
		index++
	}
	if c&uint16(IMAGE_FILE_DEBUG_STRIPPED) != 0 {
		fmt.Printf("    %d.调试信息已删除，并分别存储在另一个文件中\n", index)
		index++
	}
	if c&uint16(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) != 0 {
		fmt.Printf("    %d.如果文件位于可移动介质上，请将其复制到本地并在本地运行\n", index)
		index++
	}
	if c&uint16(IMAGE_FILE_NET_RUN_FROM_SWAP) != 0 {
		fmt.Printf("    %d.如果文件在网络上，请将其复制到本地并在本地运行\n", index)
		index++
	}
	if c&uint16(IMAGE_FILE_SYSTEM) != 0 {
		fmt.Printf("    %d.该文件是系统文件\n", index)
		index++
	}
	if c&uint16(IMAGE_FILE_DLL) != 0 {
		fmt.Printf("    %d.该文件是一个DLL文件。虽然是可执行文件，但不能直接运行。\n", index)
		index++
	}
	if c&uint16(IMAGE_FILE_UP_SYSTEM_ONLY) != 0 {
		fmt.Printf("    %d.该文件应仅在单处理器计算机上运行\n", index)
		index++
	}
}

func printOptionalHeader32(head *pe.OptionalHeader32) {
	fmt.Println("Option header32:")

	fmt.Printf("\tMagic: %d(0x%X)\n", head.Magic, head.Magic)

	fmt.Println("\t代码段大小:", head.SizeOfCode)

	fmt.Println("\t初始化数据段的大小:", head.SizeOfInitializedData)

	fmt.Println("\t未初始化数据段的大小:", head.SizeOfUninitializedData)

	fmt.Printf("\t内存对齐方式: 0x%X\n", head.SectionAlignment)

	fmt.Printf("\t文件对齐方式: 0x%X\n", head.FileAlignment)

	fmt.Printf("\t程序执行入口: 0x%X\n", head.AddressOfEntryPoint)

	fmt.Printf("\t代码段起始地址: 0x%X\n", head.BaseOfCode)

	fmt.Printf("\t进程首选基址: 0x%X\n", head.ImageBase)

	for i := 0; i < 15; i++ {
		dataDir := head.DataDirectory[i]
		fmt.Printf("\t%s: virtual address: 0x%X\n", DataDirectory[uint16(i)], dataDir.VirtualAddress)
	}
}

func printOptionalHeader64(head *pe.OptionalHeader64) {
	fmt.Println("Option header64:")

	fmt.Printf("\tMagic: %d(0x%X)\n", head.Magic, head.Magic)

	fmt.Println("\t代码段大小:", head.SizeOfCode)

	fmt.Println("\t初始化数据段的大小:", head.SizeOfInitializedData)

	fmt.Println("\t未初始化数据段的大小:", head.SizeOfUninitializedData)

	fmt.Printf("\t内存对齐方式: 0x%X\n", head.SectionAlignment)

	fmt.Printf("\t文件对齐方式: 0x%X\n", head.FileAlignment)

	fmt.Printf("\t程序执行入口: 0x%X\n", head.AddressOfEntryPoint)

	fmt.Printf("\t代码段起始地址: 0x%X\n", head.BaseOfCode)

	fmt.Printf("\t进程首选基址: 0x%X\n", head.ImageBase)

	for i := 0; i < 15; i++ {
		dataDir := head.DataDirectory[i]
		fmt.Printf("\t%s: virtual address: 0x%X\n", DataDirectory[uint16(i)], dataDir.VirtualAddress)
	}
}

func printSectionTable(sections []*pe.Section) {
	fmt.Println("section tables:")
	for i, section := range sections {
		fmt.Printf("%02d %s:\n", i+1, section.Name)
		fmt.Printf("\tVirtualSize: 0x%X, VirtualAddress: 0x%X\n", section.VirtualSize, section.VirtualAddress)
		fmt.Printf("\tRawSize: 0x%X, RawOffset: 0x%X\n", section.Size, section.Offset)
		fmt.Printf("\tPointerToRelocations: 0x%X, PointerToLineNumbers: 0x%X\n", section.PointerToRelocations, section.PointerToLineNumbers)
		fmt.Printf("\tNumberOfRelocations: 0x%X, NumberOfLineNumbers: 0x%X\n", section.NumberOfRelocations, section.NumberOfLineNumbers)
		fmt.Printf("\tCharacteristics: 0x%X\n", section.Characteristics)
	}
}

func printSymbols(symbols []*pe.Symbol) {
	fmt.Printf("symbol tables:")
	if len(symbols) == 0 {
		fmt.Printf(" nil\n")
		return
	}
	fmt.Printf("\n")
	for i, symbol := range symbols {
		fmt.Printf("%02d %s:\n", i+1, symbol.Name)
		fmt.Printf("Value: 0x%X\n", symbol.Value)
		fmt.Printf("Type: 0x%X\n", symbol.Type)
		fmt.Printf("StorageClass: 0x%X\n", symbol.StorageClass)
	}
}

func printImportTable(file *pe.File) {
	importTable, _ := file.ImportedSymbols()
	fmt.Println("import table:")
	for _, symbol := range importTable {
		fmt.Println(symbol)
	}
}

func PrintPEFile(file *pe.File) {
	//-------------- parse FileHeader -----------------
	printMachine(file.FileHeader.Machine)
	printSections(file.FileHeader.NumberOfSections)
	printTimeDateStamp(file.FileHeader.TimeDateStamp)
	printPointerToSymbolTable(&file.FileHeader)
	fmt.Printf("OptionalHeader长度: %d(0x%X)\n", file.FileHeader.SizeOfOptionalHeader, file.FileHeader.SizeOfOptionalHeader)
	printCharacteristics(file.FileHeader.Characteristics)

	//-------------- parse OptionalHeader -----------------
	switch file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		option := file.OptionalHeader.(*pe.OptionalHeader32)
		printOptionalHeader32(option)
	case *pe.OptionalHeader64:
		option := file.OptionalHeader.(*pe.OptionalHeader64)
		printOptionalHeader64(option)
	}
	printSectionTable(file.Sections)
	printSymbols(file.Symbols)
	printImportTable(file)
}

func PrintExit(a ...interface{}) {
	fmt.Println(a)
	os.Exit(-1)
}

func main() {
	args := os.Args
	if len(args) != 2 {
		PrintExit("usage: ./ReadPE.exe $PATH")
	}

	file, err := pe.Open(args[1])
	if err != nil {
		PrintExit("can't open file:", args[0])
	}
	PrintPEFile(file)
}
