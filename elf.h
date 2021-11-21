#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
// BASED ON llvm/include/llvm/BinaryFormat/ELF.h

#define Elf32_Addr uint32_t // Program address
#define Elf32_Off uint32_t // File offset
#define Elf32_Half uint16_t
#define Elf32_Word uint32_t
#define Elf32_Sword int32_t

#define Elf64_Addr uint64_t
#define Elf64_Off uint64_t
#define Elf64_Half uint16_t
#define Elf64_Word uint32_t
#define Elf64_Sword int32_t
#define Elf64_Xword uint64_t
#define Elf64_Sxword int64_t

// Object file magic string.
static const char ElfMagic[] = {0x7f, 'E', 'L', 'F', '\0'};

// e_ident size and indices.
enum {
	EI_MAG0 = 0, // File identification index.
	EI_MAG1 = 1, // File identification index.
	EI_MAG2 = 2, // File identification index.
	EI_MAG3 = 3, // File identification index.
	EI_CLASS = 4, // File class.
	EI_DATA = 5, // Data encoding.
	EI_VERSION = 6, // File version.
	EI_OSABI = 7, // OS/ABI identification.
	EI_ABIVERSION = 8, // ABI version.
	EI_PAD = 9, // Start of padding bytes.
	EI_NIDENT = 16 // Number of bytes in e_ident.
};

struct Elf32_Ehdr {
	unsigned char e_ident[EI_NIDENT]; // ELF Identification bytes
	Elf32_Half e_type; // Type of file (see ET_* below)
	Elf32_Half e_machine; // Required architecture for this file (see EM_*)
	Elf32_Word e_version; // Must be equal to 1
	Elf32_Addr e_entry; // Address to jump to in order to start program
	Elf32_Off e_phoff; // Program header table's file offset, in bytes
	Elf32_Off e_shoff; // Section header table's file offset, in bytes
	Elf32_Word e_flags; // Processor-specific flags
	Elf32_Half e_ehsize; // Size of ELF header, in bytes
	Elf32_Half e_phentsize; // Size of an entry in the program header table
	Elf32_Half e_phnum; // Number of entries in the program header table
	Elf32_Half e_shentsize; // Size of an entry in the section header table
	Elf32_Half e_shnum; // Number of entries in the section header table
	Elf32_Half e_shstrndx; // Sect hdr table index of sect name string table

	// bool checkMagic() const
	// {
	// 	return (memcmp(e_ident, ElfMagic, strlen(ElfMagic))) == 0;
	// }

	// unsigned char getFileClass() const { return e_ident[EI_CLASS]; }
	// unsigned char getDataEncoding() const { return e_ident[EI_DATA]; }
};

// 64-bit ELF header. Fields are the same as for ELF32, but with different
// types (see above).
struct Elf64_Ehdr {
	unsigned char e_ident[EI_NIDENT];
	Elf64_Half e_type;
	Elf64_Half e_machine;
	Elf64_Word e_version;
	Elf64_Addr e_entry;
	Elf64_Off e_phoff;
	Elf64_Off e_shoff;
	Elf64_Word e_flags;
	Elf64_Half e_ehsize;
	Elf64_Half e_phentsize;
	Elf64_Half e_phnum;
	Elf64_Half e_shentsize;
	Elf64_Half e_shnum;
	Elf64_Half e_shstrndx;
};


// unsigned char getDataEncoding() const { return e_ident[EI_DATA]; }

unsigned char get_file_class(struct Elf64_Ehdr *ehdr);

bool check_magic(struct Elf64_Ehdr *ehdr);

// File types
enum {
	ET_NONE = 0, // No file type
	ET_REL = 1, // Relocatable file
	ET_EXEC = 2, // Executable file
	ET_DYN = 3, // Shared object file
	ET_CORE = 4, // Core file
	ET_LOPROC = 0xff00, // Beginning of processor-specific codes
	ET_HIPROC = 0xffff // Processor-specific
};

// Versioning
enum { EV_NONE = 0,
	EV_CURRENT = 1 };

// Machine architectures
// See current registered ELF machine architectures at:
//    http://www.uxsglobal.com/developers/gabi/latest/ch4.eheader.html
enum {
	EM_NONE = 0, // No machine
	EM_M32 = 1, // AT&T WE 32100
	EM_SPARC = 2, // SPARC
	EM_386 = 3, // Intel 386
	EM_68K = 4, // Motorola 68000
	EM_88K = 5, // Motorola 88000
	EM_IAMCU = 6, // Intel MCU
	EM_860 = 7, // Intel 80860
	EM_MIPS = 8, // MIPS R3000
	EM_S370 = 9, // IBM System/370
	EM_MIPS_RS3_LE = 10, // MIPS RS3000 Little-endian
	EM_PARISC = 15, // Hewlett-Packard PA-RISC
	EM_VPP500 = 17, // Fujitsu VPP500
	EM_SPARC32PLUS = 18, // Enhanced instruction set SPARC
	EM_960 = 19, // Intel 80960
	EM_PPC = 20, // PowerPC
	EM_PPC64 = 21, // PowerPC64
	EM_S390 = 22, // IBM System/390
	EM_SPU = 23, // IBM SPU/SPC
	EM_V800 = 36, // NEC V800
	EM_FR20 = 37, // Fujitsu FR20
	EM_RH32 = 38, // TRW RH-32
	EM_RCE = 39, // Motorola RCE
	EM_ARM = 40, // ARM
	EM_ALPHA = 41, // DEC Alpha
	EM_SH = 42, // Hitachi SH
	EM_SPARCV9 = 43, // SPARC V9
	EM_TRICORE = 44, // Siemens TriCore
	EM_ARC = 45, // Argonaut RISC Core
	EM_H8_300 = 46, // Hitachi H8/300
	EM_H8_300H = 47, // Hitachi H8/300H
	EM_H8S = 48, // Hitachi H8S
	EM_H8_500 = 49, // Hitachi H8/500
	EM_IA_64 = 50, // Intel IA-64 processor architecture
	EM_MIPS_X = 51, // Stanford MIPS-X
	EM_COLDFIRE = 52, // Motorola ColdFire
	EM_68HC12 = 53, // Motorola M68HC12
	EM_MMA = 54, // Fujitsu MMA Multimedia Accelerator
	EM_PCP = 55, // Siemens PCP
	EM_NCPU = 56, // Sony nCPU embedded RISC processor
	EM_NDR1 = 57, // Denso NDR1 microprocessor
	EM_STARCORE = 58, // Motorola Star*Core processor
	EM_ME16 = 59, // Toyota ME16 processor
	EM_ST100 = 60, // STMicroelectronics ST100 processor
	EM_TINYJ = 61, // Advanced Logic Corp. TinyJ embedded processor family
	EM_X86_64 = 62, // AMD x86-64 architecture
	EM_PDSP = 63, // Sony DSP Processor
	EM_PDP10 = 64, // Digital Equipment Corp. PDP-10
	EM_PDP11 = 65, // Digital Equipment Corp. PDP-11
	EM_FX66 = 66, // Siemens FX66 microcontroller
	EM_ST9PLUS = 67, // STMicroelectronics ST9+ 8/16 bit microcontroller
	EM_ST7 = 68, // STMicroelectronics ST7 8-bit microcontroller
	EM_68HC16 = 69, // Motorola MC68HC16 Microcontroller
	EM_68HC11 = 70, // Motorola MC68HC11 Microcontroller
	EM_68HC08 = 71, // Motorola MC68HC08 Microcontroller
	EM_68HC05 = 72, // Motorola MC68HC05 Microcontroller
	EM_SVX = 73, // Silicon Graphics SVx
	EM_ST19 = 74, // STMicroelectronics ST19 8-bit microcontroller
	EM_VAX = 75, // Digital VAX
	EM_CRIS = 76, // Axis Communications 32-bit embedded processor
	EM_JAVELIN = 77, // Infineon Technologies 32-bit embedded processor
	EM_FIREPATH = 78, // Element 14 64-bit DSP Processor
	EM_ZSP = 79, // LSI Logic 16-bit DSP Processor
	EM_MMIX = 80, // Donald Knuth's educational 64-bit processor
	EM_HUANY = 81, // Harvard University machine-independent object files
	EM_PRISM = 82, // SiTera Prism
	EM_AVR = 83, // Atmel AVR 8-bit microcontroller
	EM_FR30 = 84, // Fujitsu FR30
	EM_D10V = 85, // Mitsubishi D10V
	EM_D30V = 86, // Mitsubishi D30V
	EM_V850 = 87, // NEC v850
	EM_M32R = 88, // Mitsubishi M32R
	EM_MN10300 = 89, // Matsushita MN10300
	EM_MN10200 = 90, // Matsushita MN10200
	EM_PJ = 91, // picoJava
	EM_OPENRISC = 92, // OpenRISC 32-bit embedded processor
	EM_ARC_COMPACT = 93, // ARC International ARCompact processor (old
	// spelling/synonym: EM_ARC_A5)
	EM_XTENSA = 94, // Tensilica Xtensa Architecture
	EM_VIDEOCORE = 95, // Alphamosaic VideoCore processor
	EM_TMM_GPP = 96, // Thompson Multimedia General Purpose Processor
	EM_NS32K = 97, // National Semiconductor 32000 series
	EM_TPC = 98, // Tenor Network TPC processor
	EM_SNP1K = 99, // Trebia SNP 1000 processor
	EM_ST200 = 100, // STMicroelectronics (www.st.com) ST200
	EM_IP2K = 101, // Ubicom IP2xxx microcontroller family
	EM_MAX = 102, // MAX Processor
	EM_CR = 103, // National Semiconductor CompactRISC microprocessor
	EM_F2MC16 = 104, // Fujitsu F2MC16
	EM_MSP430 = 105, // Texas Instruments embedded microcontroller msp430
	EM_BLACKFIN = 106, // Analog Devices Blackfin (DSP) processor
	EM_SE_C33 = 107, // S1C33 Family of Seiko Epson processors
	EM_SEP = 108, // Sharp embedded microprocessor
	EM_ARCA = 109, // Arca RISC Microprocessor
	EM_UNICORE = 110, // Microprocessor series from PKU-Unity Ltd. and MPRC
	// of Peking University
	EM_EXCESS = 111, // eXcess: 16/32/64-bit configurable embedded CPU
	EM_DXP = 112, // Icera Semiconductor Inc. Deep Execution Processor
	EM_ALTERA_NIOS2 = 113, // Altera Nios II soft-core processor
	EM_CRX = 114, // National Semiconductor CompactRISC CRX
	EM_XGATE = 115, // Motorola XGATE embedded processor
	EM_C166 = 116, // Infineon C16x/XC16x processor
	EM_M16C = 117, // Renesas M16C series microprocessors
	EM_DSPIC30F = 118, // Microchip Technology dsPIC30F Digital Signal
	// Controller
	EM_CE = 119, // Freescale Communication Engine RISC core
	EM_M32C = 120, // Renesas M32C series microprocessors
	EM_TSK3000 = 131, // Altium TSK3000 core
	EM_RS08 = 132, // Freescale RS08 embedded processor
	EM_SHARC = 133, // Analog Devices SHARC family of 32-bit DSP
	// processors
	EM_ECOG2 = 134, // Cyan Technology eCOG2 microprocessor
	EM_SCORE7 = 135, // Sunplus S+core7 RISC processor
	EM_DSP24 = 136, // New Japan Radio (NJR) 24-bit DSP Processor
	EM_VIDEOCORE3 = 137, // Broadcom VideoCore III processor
	EM_LATTICEMICO32 = 138, // RISC processor for Lattice FPGA architecture
	EM_SE_C17 = 139, // Seiko Epson C17 family
	EM_TI_C6000 = 140, // The Texas Instruments TMS320C6000 DSP family
	EM_TI_C2000 = 141, // The Texas Instruments TMS320C2000 DSP family
	EM_TI_C5500 = 142, // The Texas Instruments TMS320C55x DSP family
	EM_MMDSP_PLUS = 160, // STMicroelectronics 64bit VLIW Data Signal Processor
	EM_CYPRESS_M8C = 161, // Cypress M8C microprocessor
	EM_R32C = 162, // Renesas R32C series microprocessors
	EM_TRIMEDIA = 163, // NXP Semiconductors TriMedia architecture family
	EM_HEXAGON = 164, // Qualcomm Hexagon processor
	EM_8051 = 165, // Intel 8051 and variants
	EM_STXP7X = 166, // STMicroelectronics STxP7x family of configurable
	// and extensible RISC processors
	EM_NDS32 = 167, // Andes Technology compact code size embedded RISC
	// processor family
	EM_ECOG1 = 168, // Cyan Technology eCOG1X family
	EM_ECOG1X = 168, // Cyan Technology eCOG1X family
	EM_MAXQ30 = 169, // Dallas Semiconductor MAXQ30 Core Micro-controllers
	EM_XIMO16 = 170, // New Japan Radio (NJR) 16-bit DSP Processor
	EM_MANIK = 171, // M2000 Reconfigurable RISC Microprocessor
	EM_CRAYNV2 = 172, // Cray Inc. NV2 vector architecture
	EM_RX = 173, // Renesas RX family
	EM_METAG = 174, // Imagination Technologies META processor
	// architecture
	EM_MCST_ELBRUS = 175, // MCST Elbrus general purpose hardware architecture
	EM_ECOG16 = 176, // Cyan Technology eCOG16 family
	EM_CR16 = 177, // National Semiconductor CompactRISC CR16 16-bit
	// microprocessor
	EM_ETPU = 178, // Freescale Extended Time Processing Unit
	EM_SLE9X = 179, // Infineon Technologies SLE9X core
	EM_L10M = 180, // Intel L10M
	EM_K10M = 181, // Intel K10M
	EM_AARCH64 = 183, // ARM AArch64
	EM_AVR32 = 185, // Atmel Corporation 32-bit microprocessor family
	EM_STM8 = 186, // STMicroeletronics STM8 8-bit microcontroller
	EM_TILE64 = 187, // Tilera TILE64 multicore architecture family
	EM_TILEPRO = 188, // Tilera TILEPro multicore architecture family
	EM_CUDA = 190, // NVIDIA CUDA architecture
	EM_TILEGX = 191, // Tilera TILE-Gx multicore architecture family
	EM_CLOUDSHIELD = 192, // CloudShield architecture family
	EM_COREA_1ST = 193, // KIPO-KAIST Core-A 1st generation processor family
	EM_COREA_2ND = 194, // KIPO-KAIST Core-A 2nd generation processor family
	EM_ARC_COMPACT2 = 195, // Synopsys ARCompact V2
	EM_OPEN8 = 196, // Open8 8-bit RISC soft processor core
	EM_RL78 = 197, // Renesas RL78 family
	EM_VIDEOCORE5 = 198, // Broadcom VideoCore V processor
	EM_78KOR = 199, // Renesas 78KOR family
	EM_56800EX = 200, // Freescale 56800EX Digital Signal Controller (DSC)
	EM_BA1 = 201, // Beyond BA1 CPU architecture
	EM_BA2 = 202, // Beyond BA2 CPU architecture
	EM_XCORE = 203, // XMOS xCORE processor family
	EM_MCHP_PIC = 204, // Microchip 8-bit PIC(r) family
	EM_INTEL205 = 205, // Reserved by Intel
	EM_INTEL206 = 206, // Reserved by Intel
	EM_INTEL207 = 207, // Reserved by Intel
	EM_INTEL208 = 208, // Reserved by Intel
	EM_INTEL209 = 209, // Reserved by Intel
	EM_KM32 = 210, // KM211 KM32 32-bit processor
	EM_KMX32 = 211, // KM211 KMX32 32-bit processor
	EM_KMX16 = 212, // KM211 KMX16 16-bit processor
	EM_KMX8 = 213, // KM211 KMX8 8-bit processor
	EM_KVARC = 214, // KM211 KVARC processor
	EM_CDP = 215, // Paneve CDP architecture family
	EM_COGE = 216, // Cognitive Smart Memory Processor
	EM_COOL = 217, // iCelero CoolEngine
	EM_NORC = 218, // Nanoradio Optimized RISC
	EM_CSR_KALIMBA = 219, // CSR Kalimba architecture family
	EM_AMDGPU = 224, // AMD GPU architecture
	EM_RISCV = 243, // RISC-V
	EM_LANAI = 244, // Lanai 32-bit processor
	EM_BPF = 247, // Linux kernel bpf virtual machine
	EM_VE = 251, // NEC SX-Aurora VE
};

// Object file classes.
enum {
	ELFCLASSNONE = 0,
	ELFCLASS32 = 1, // 32-bit object file
	ELFCLASS64 = 2 // 64-bit object file
};

// Object file byte orderings.
enum {
	ELFDATANONE = 0, // Invalid data encoding.
	ELFDATA2LSB = 1, // Little-endian object file
	ELFDATA2MSB = 2 // Big-endian object file
};

// OS ABI identification.
enum {
	ELFOSABI_NONE = 0, // UNIX System V ABI
	ELFOSABI_HPUX = 1, // HP-UX operating system
	ELFOSABI_NETBSD = 2, // NetBSD
	ELFOSABI_GNU = 3, // GNU/Linux
	ELFOSABI_LINUX = 3, // Historical alias for ELFOSABI_GNU.
	ELFOSABI_HURD = 4, // GNU/Hurd
	ELFOSABI_SOLARIS = 6, // Solaris
	ELFOSABI_AIX = 7, // AIX
	ELFOSABI_IRIX = 8, // IRIX
	ELFOSABI_FREEBSD = 9, // FreeBSD
	ELFOSABI_TRU64 = 10, // TRU64 UNIX
	ELFOSABI_MODESTO = 11, // Novell Modesto
	ELFOSABI_OPENBSD = 12, // OpenBSD
	ELFOSABI_OPENVMS = 13, // OpenVMS
	ELFOSABI_NSK = 14, // Hewlett-Packard Non-Stop Kernel
	ELFOSABI_AROS = 15, // AROS
	ELFOSABI_FENIXOS = 16, // FenixOS
	ELFOSABI_CLOUDABI = 17, // Nuxi CloudABI
	ELFOSABI_FIRST_ARCH = 64, // First architecture-specific OS ABI
	ELFOSABI_AMDGPU_HSA = 64, // AMD HSA runtime
	ELFOSABI_AMDGPU_PAL = 65, // AMD PAL runtime
	ELFOSABI_AMDGPU_MESA3D = 66, // AMD GCN GPUs (GFX6+) for MESA runtime
	ELFOSABI_ARM = 97, // ARM
	ELFOSABI_C6000_ELFABI = 64, // Bare-metal TMS320C6000
	ELFOSABI_C6000_LINUX = 65, // Linux TMS320C6000
	ELFOSABI_STANDALONE = 255, // Standalone (embedded) application
	ELFOSABI_LAST_ARCH = 255 // Last Architecture-specific OS ABI
};

#define ELF_RELOC(name, value) name = value,

// X86_64 relocations.
//  enum {
//  #include "ELFRelocs/x86_64.def"
//  };

//  // i386 relocations.
//  enum {
//  #include "ELFRelocs/i386.def"
//  };

//  // ELF Relocation types for PPC32
//  enum {
//  #include "ELFRelocs/PowerPC.def"
//  };

// Specific e_flags for PPC64
enum {
	// e_flags bits specifying ABI:
	// 1 for original ABI using function descriptors,
	// 2 for revised ABI without function descriptors,
	// 0 for unspecified or not using any features affected by the
	// differences.
	EF_PPC64_ABI = 3
};

// Special values for the st_other field in the symbol table entry for PPC64.
enum {
	STO_PPC64_LOCAL_BIT = 5,
	STO_PPC64_LOCAL_MASK = (7 << STO_PPC64_LOCAL_BIT)
};
static inline int64_t
decodePPC64LocalEntryOffset(unsigned Other)
{
	unsigned Val = (Other & STO_PPC64_LOCAL_MASK) >> STO_PPC64_LOCAL_BIT;
	return ((1 << Val) >> 2) << 2;
}

// Special values for the st_other field in the symbol table entry for MIPS.
enum {
	STO_MIPS_OPTIONAL = 0x04, // Symbol whose definition is optional
	STO_MIPS_PLT = 0x08, // PLT entry related dynamic table record
	STO_MIPS_PIC = 0x20, // PIC func in an object mixes PIC/non-PIC
	STO_MIPS_MICROMIPS = 0x80, // MIPS Specific ISA for MicroMips
	STO_MIPS_MIPS16 = 0xf0 // MIPS Specific ISA for Mips16
};

// .MIPS.options section descriptor kinds
enum {
	ODK_NULL = 0, // Undefined
	ODK_REGINFO = 1, // Register usage information
	ODK_EXCEPTIONS = 2, // Exception processing options
	ODK_PAD = 3, // Section padding options
	ODK_HWPATCH = 4, // Hardware patches applied
	ODK_FILL = 5, // Linker fill value
	ODK_TAGS = 6, // Space for tool identification
	ODK_HWAND = 7, // Hardware AND patches applied
	ODK_HWOR = 8, // Hardware OR patches applied
	ODK_GP_GROUP = 9, // GP group to use for text/data sections
	ODK_IDENT = 10, // ID information
	ODK_PAGESIZE = 11 // Page size information
};

// Hexagon-specific e_flags
enum {
	// Object processor version flags, bits[11:0]
	EF_HEXAGON_MACH_V2 = 0x00000001, // Hexagon V2
	EF_HEXAGON_MACH_V3 = 0x00000002, // Hexagon V3
	EF_HEXAGON_MACH_V4 = 0x00000003, // Hexagon V4
	EF_HEXAGON_MACH_V5 = 0x00000004, // Hexagon V5
	EF_HEXAGON_MACH_V55 = 0x00000005, // Hexagon V55
	EF_HEXAGON_MACH_V60 = 0x00000060, // Hexagon V60
	EF_HEXAGON_MACH_V62 = 0x00000062, // Hexagon V62
	EF_HEXAGON_MACH_V65 = 0x00000065, // Hexagon V65
	EF_HEXAGON_MACH_V66 = 0x00000066, // Hexagon V66
	EF_HEXAGON_MACH_V67 = 0x00000067, // Hexagon V67
	EF_HEXAGON_MACH_V67T = 0x00008067, // Hexagon V67T

	// Highest ISA version flags
	EF_HEXAGON_ISA_MACH = 0x00000000, // Same as specified in bits[11:0]
	// of e_flags
	EF_HEXAGON_ISA_V2 = 0x00000010, // Hexagon V2 ISA
	EF_HEXAGON_ISA_V3 = 0x00000020, // Hexagon V3 ISA
	EF_HEXAGON_ISA_V4 = 0x00000030, // Hexagon V4 ISA
	EF_HEXAGON_ISA_V5 = 0x00000040, // Hexagon V5 ISA
	EF_HEXAGON_ISA_V55 = 0x00000050, // Hexagon V55 ISA
	EF_HEXAGON_ISA_V60 = 0x00000060, // Hexagon V60 ISA
	EF_HEXAGON_ISA_V62 = 0x00000062, // Hexagon V62 ISA
	EF_HEXAGON_ISA_V65 = 0x00000065, // Hexagon V65 ISA
	EF_HEXAGON_ISA_V66 = 0x00000066, // Hexagon V66 ISA
	EF_HEXAGON_ISA_V67 = 0x00000067, // Hexagon V67 ISA
};

// Hexagon-specific section indexes for common small data
enum {
	SHN_HEXAGON_SCOMMON = 0xff00, // Other access sizes
	SHN_HEXAGON_SCOMMON_1 = 0xff01, // Byte-sized access
	SHN_HEXAGON_SCOMMON_2 = 0xff02, // Half-word-sized access
	SHN_HEXAGON_SCOMMON_4 = 0xff03, // Word-sized access
	SHN_HEXAGON_SCOMMON_8 = 0xff04 // Double-word-size access
};

#undef ELF_RELOC

// Section header.
struct Elf32_Shdr {
	Elf32_Word sh_name; // Section name (index into string table)
	Elf32_Word sh_type; // Section type (SHT_*)
	Elf32_Word sh_flags; // Section flags (SHF_*)
	Elf32_Addr sh_addr; // Address where section is to be loaded
	Elf32_Off sh_offset; // File offset of section data, in bytes
	Elf32_Word sh_size; // Size of section, in bytes
	Elf32_Word sh_link; // Section type-specific header table index link
	Elf32_Word sh_info; // Section type-specific extra information
	Elf32_Word sh_addralign; // Section address alignment
	Elf32_Word sh_entsize; // Size of records contained within the section
};

// Section header for ELF64 - same fields as ELF32, different types.
struct Elf64_Shdr {
	Elf64_Word sh_name;
	Elf64_Word sh_type;
	Elf64_Xword sh_flags;
	Elf64_Addr sh_addr;
	Elf64_Off sh_offset;
	Elf64_Xword sh_size;
	Elf64_Word sh_link;
	Elf64_Word sh_info;
	Elf64_Xword sh_addralign;
	Elf64_Xword sh_entsize;
};

// Special section indices.
enum {
	SHN_UNDEF = 0, // Undefined, missing, irrelevant, or meaningless
	SHN_LORESERVE = 0xff00, // Lowest reserved index
	SHN_LOPROC = 0xff00, // Lowest processor-specific index
	SHN_HIPROC = 0xff1f, // Highest processor-specific index
	SHN_LOOS = 0xff20, // Lowest operating system-specific index
	SHN_HIOS = 0xff3f, // Highest operating system-specific index
	SHN_ABS = 0xfff1, // Symbol has absolute value; does not need relocation
	SHN_COMMON = 0xfff2, // FORTRAN COMMON or C external global variables
	SHN_XINDEX = 0xffff, // Mark that the index is >= SHN_LORESERVE
	SHN_HIRESERVE = 0xffff // Highest reserved index
};

// Section types.
enum {
	SHT_NULL = 0, // No associated section (inactive entry).
	SHT_PROGBITS = 1, // Program-defined contents.
	SHT_SYMTAB = 2, // Symbol table.
	SHT_STRTAB = 3, // String table.
	SHT_RELA = 4, // Relocation entries; explicit addends.
	SHT_HASH = 5, // Symbol hash table.
	SHT_DYNAMIC = 6, // Information for dynamic linking.
	SHT_NOTE = 7, // Information about the file.
	SHT_NOBITS = 8, // Data occupies no space in the file.
	SHT_REL = 9, // Relocation entries; no explicit addends.
	SHT_SHLIB = 10, // Reserved.
	SHT_DYNSYM = 11, // Symbol table.
	SHT_INIT_ARRAY = 14, // Pointers to initialization functions.
	SHT_FINI_ARRAY = 15, // Pointers to termination functions.
	SHT_PREINIT_ARRAY = 16, // Pointers to pre-init functions.
	SHT_GROUP = 17, // Section group.
	SHT_SYMTAB_SHNDX = 18, // Indices for SHN_XINDEX entries.
	// Experimental support for SHT_RELR sections. For details, see proposal
	// at https://groups.google.com/forum/#!topic/generic-abi/bX460iggiKg
	SHT_RELR = 19, // Relocation entries; only offsets.
	SHT_LOOS = 0x60000000, // Lowest operating system-specific type.
	// Android packed relocation section types.
	// https://android.googlesource.com/platform/bionic/+/6f12bfece5dcc01325e0abba56a46b1bcf991c69/tools/relocation_packer/src/elf_file.cc#37
	SHT_ANDROID_REL = 0x60000001,
	SHT_ANDROID_RELA = 0x60000002,
	SHT_LLVM_ODRTAB = 0x6fff4c00, // LLVM ODR table.
	SHT_LLVM_LINKER_OPTIONS = 0x6fff4c01, // LLVM Linker Options.
	SHT_LLVM_CALL_GRAPH_PROFILE = 0x6fff4c02, // LLVM Call Graph Profile.
	SHT_LLVM_ADDRSIG = 0x6fff4c03, // List of address-significant symbols
	// for safe ICF.
	SHT_LLVM_DEPENDENT_LIBRARIES = 0x6fff4c04, // LLVM Dependent Library Specifiers.
	SHT_LLVM_SYMPART = 0x6fff4c05, // Symbol partition specification.
	SHT_LLVM_PART_EHDR = 0x6fff4c06, // ELF header for loadable partition.
	SHT_LLVM_PART_PHDR = 0x6fff4c07, // Phdrs for loadable partition.
	// Android's experimental support for SHT_RELR sections.
	// https://android.googlesource.com/platform/bionic/+/b7feec74547f84559a1467aca02708ff61346d2a/libc/include/elf.h#512
	SHT_ANDROID_RELR = 0x6fffff00, // Relocation entries; only offsets.
	SHT_GNU_ATTRIBUTES = 0x6ffffff5, // Object attributes.
	SHT_GNU_HASH = 0x6ffffff6, // GNU-style hash table.
	SHT_GNU_verdef = 0x6ffffffd, // GNU version definitions.
	SHT_GNU_verneed = 0x6ffffffe, // GNU version references.
	SHT_GNU_versym = 0x6fffffff, // GNU symbol versions table.
	SHT_HIOS = 0x6fffffff, // Highest operating system-specific type.
	SHT_LOPROC = 0x70000000, // Lowest processor arch-specific type.
	// Fixme: All this is duplicated in MCSectionELF. Why??
	// Exception Index table
	SHT_ARM_EXIDX = 0x70000001U,
	// BPABI DLL dynamic linking pre-emption map
	SHT_ARM_PREEMPTMAP = 0x70000002U,
	//  Object file compatibility attributes
	SHT_ARM_ATTRIBUTES = 0x70000003U,
	SHT_ARM_DEBUGOVERLAY = 0x70000004U,
	SHT_ARM_OVERLAYSECTION = 0x70000005U,
	SHT_HEX_ORDERED = 0x70000000, // Link editor is to sort the entries in
	// this section based on their sizes
	SHT_X86_64_UNWIND = 0x70000001, // Unwind information

	SHT_MIPS_REGINFO = 0x70000006, // Register usage information
	SHT_MIPS_OPTIONS = 0x7000000d, // General options
	SHT_MIPS_DWARF = 0x7000001e, // DWARF debugging section.
	SHT_MIPS_ABIFLAGS = 0x7000002a, // ABI information.

	SHT_MSP430_ATTRIBUTES = 0x70000003U,

	SHT_RISCV_ATTRIBUTES = 0x70000003U,

	SHT_HIPROC = 0x7fffffff, // Highest processor arch-specific type.
	SHT_LOUSER = 0x80000000, // Lowest type reserved for applications.
	SHT_HIUSER = 0xffffffff // Highest type reserved for applications.
};

// Section flags.
enum {
	// Section data should be writable during execution.
	SHF_WRITE = 0x1,

	// Section occupies memory during program execution.
	SHF_ALLOC = 0x2,

	// Section contains executable machine instructions.
	SHF_EXECINSTR = 0x4,

	// The data in this section may be merged.
	SHF_MERGE = 0x10,

	// The data in this section is null-terminated strings.
	SHF_STRINGS = 0x20,

	// A field in this section holds a section header table index.
	SHF_INFO_LINK = 0x40U,

	// Adds special ordering requirements for link editors.
	SHF_LINK_ORDER = 0x80U,

	// This section requires special OS-specific processing to avoid
	// incorrect
	// behavior.
	SHF_OS_NONCONFORMING = 0x100U,

	// This section is a member of a section group.
	SHF_GROUP = 0x200U,

	// This section holds Thread-Local Storage.
	SHF_TLS = 0x400U,

	// Identifies a section containing compressed data.
	SHF_COMPRESSED = 0x800U,

	// This section is excluded from the final executable or shared library.
	SHF_EXCLUDE = 0x80000000U,

	// Start of target-specific flags.

	SHF_MASKOS = 0x0ff00000,

	// Bits indicating processor-specific flags.
	SHF_MASKPROC = 0xf0000000,

	/// All sections with the "d" flag are grouped together by the linker to
	/// form
	/// the data section and the dp register is set to the start of the
	/// section by
	/// the boot code.
	XCORE_SHF_DP_SECTION = 0x10000000,

	/// All sections with the "c" flag are grouped together by the linker to
	/// form
	/// the constant pool and the cp register is set to the start of the
	/// constant
	/// pool by the boot code.
	XCORE_SHF_CP_SECTION = 0x20000000,

	// If an object file section does not have this flag set, then it may
	// not hold
	// more than 2GB and can be freely referred to in objects using smaller
	// code
	// models. Otherwise, only objects using larger code models can refer to
	// them.
	// For example, a medium code model object can refer to data in a
	// section that
	// sets this flag besides being able to refer to data in a section that
	// does
	// not set it; likewise, a small code model object can refer only to
	// code in a
	// section that does not set this flag.
	SHF_X86_64_LARGE = 0x10000000,

	// All sections with the GPREL flag are grouped into a global data area
	// for faster accesses
	SHF_HEX_GPREL = 0x10000000,

	// Section contains text/data which may be replicated in other sections.
	// Linker must retain only one copy.
	SHF_MIPS_NODUPES = 0x01000000,

	// Linker must generate implicit hidden weak names.
	SHF_MIPS_NAMES = 0x02000000,

	// Section data local to process.
	SHF_MIPS_LOCAL = 0x04000000,

	// Do not strip this section.
	SHF_MIPS_NOSTRIP = 0x08000000,

	// Section must be part of global data area.
	SHF_MIPS_GPREL = 0x10000000,

	// This section should be merged.
	SHF_MIPS_MERGE = 0x20000000,

	// Address size to be inferred from section entry size.
	SHF_MIPS_ADDR = 0x40000000,

	// Section data is string data by default.
	SHF_MIPS_STRING = 0x80000000,

	// Make code section unreadable when in execute-only mode
	SHF_ARM_PURECODE = 0x20000000
};

// Section Group Flags
enum {
	GRP_COMDAT = 0x1,
	GRP_MASKOS = 0x0ff00000,
	GRP_MASKPROC = 0xf0000000
};

// Symbol table entries for ELF32.
struct Elf32_Sym {
	Elf32_Word st_name; // Symbol name (index into string table)
	Elf32_Addr st_value; // Value or address associated with the symbol
	Elf32_Word st_size; // Size of the symbol
	unsigned char st_info; // Symbol's type and binding attributes
	unsigned char st_other; // Must be zero; reserved
	Elf32_Half
	    st_shndx; // Which section (header table index) it's defined in

	// These accessors and mutators correspond to the ELF32_ST_BIND,
	// ELF32_ST_TYPE, and ELF32_ST_INFO macros defined in the ELF
	// specification:
	// unsigned char getBinding() const { return st_info >> 4; }
	// unsigned char getType() const { return st_info & 0x0f; }
	// void setBinding(unsigned char b) { setBindingAndType(b, getType()); }
	// void setType(unsigned char t) { setBindingAndType(getBinding(), t); }
	// void setBindingAndType(unsigned char b, unsigned char t)
	// {
	// 	st_info = (b << 4) + (t & 0x0f);
	// }
};

// Symbol table entries for ELF64.
struct Elf64_Sym {
	Elf64_Word st_name; // Symbol name (index into string table)
	unsigned char st_info; // Symbol's type and binding attributes
	unsigned char st_other; // Must be zero; reserved
	Elf64_Half st_shndx; // Which section (header tbl index) it's defined in
	Elf64_Addr st_value; // Value or address associated with the symbol
	Elf64_Xword st_size; // Size of the symbol

	// These accessors and mutators are identical to those defined for ELF32
	// symbol table entries.
	// unsigned char getBinding() const { return st_info >> 4; }
	// unsigned char getType() const { return st_info & 0x0f; }
	// void setBinding(unsigned char b) { setBindingAndType(b, getType()); }
	// void setType(unsigned char t) { setBindingAndType(getBinding(), t); }
	// void setBindingAndType(unsigned char b, unsigned char t)
	// {
	// 	st_info = (b << 4) + (t & 0x0f);
	// }
};

// The size (in bytes) of symbol table entries.
enum {
	SYMENTRY_SIZE32 = 16, // 32-bit symbol entry size
	SYMENTRY_SIZE64 = 24 // 64-bit symbol entry size.
};

// Symbol bindings.
enum {
	STB_LOCAL = 0, // Local symbol, not visible outside obj file containing def
	STB_GLOBAL = 1, // Global symbol, visible to all object files being combined
	STB_WEAK = 2, // Weak symbol, like global but lower-precedence
	STB_GNU_UNIQUE = 10,
	STB_LOOS = 10, // Lowest operating system-specific binding type
	STB_HIOS = 12, // Highest operating system-specific binding type
	STB_LOPROC = 13, // Lowest processor-specific binding type
	STB_HIPROC = 15 // Highest processor-specific binding type
};

// Symbol types.
enum {
	STT_NOTYPE = 0, // Symbol's type is not specified
	STT_OBJECT = 1, // Symbol is a data object (variable, array, etc.)
	STT_FUNC = 2, // Symbol is executable code (function, etc.)
	STT_SECTION = 3, // Symbol refers to a section
	STT_FILE = 4, // Local, absolute symbol that refers to a file
	STT_COMMON = 5, // An uninitialized common block
	STT_TLS = 6, // Thread local data object
	STT_GNU_IFUNC = 10, // GNU indirect function
	STT_LOOS = 10, // Lowest operating system-specific symbol type
	STT_HIOS = 12, // Highest operating system-specific symbol type
	STT_LOPROC = 13, // Lowest processor-specific symbol type
	STT_HIPROC = 15, // Highest processor-specific symbol type

	// AMDGPU symbol types
	STT_AMDGPU_HSA_KERNEL = 10
};

enum {
	STV_DEFAULT = 0, // Visibility is specified by binding type
	STV_INTERNAL = 1, // Defined by processor supplements
	STV_HIDDEN = 2, // Not visible to other components
	STV_PROTECTED = 3 // Visible in other components but not preemptable
};

// Symbol number.
enum { STN_UNDEF = 0 };

// Special relocation symbols used in the MIPS64 ELF relocation entries
enum {
	RSS_UNDEF = 0, // None
	RSS_GP = 1, // Value of gp
	RSS_GP0 = 2, // Value of gp used to create object being relocated
	RSS_LOC = 3 // Address of location being relocated
};

enum {
	R_X86_64_NONE = 0, /* No reloc */
	R_X86_64_64 = 1, /* Direct 64 bit  */
	R_X86_64_PC32 = 2, /* PC relative 32 bit signed */
	R_X86_64_GOT32 = 3, /* 32 bit GOT entry */
	R_X86_64_PLT32 = 4, /* 32 bit PLT address */
	R_X86_64_COPY = 5, /* Copy symbol at runtime */
	R_X86_64_GLOB_DAT = 6, /* Create GOT entry */
	R_X86_64_JUMP_SLOT = 7, /* Create PLT entry */
	R_X86_64_RELATIVE = 8, /* Adjust by program base */
	R_X86_64_GOTPCREL = 9, /* 32 bit signed PC relative
							  offset to GOT */
	R_X86_64_32 = 10, /* Direct 32 bit zero extended */
	R_X86_64_32S = 11, /* Direct 32 bit sign extended */
	R_X86_64_16 = 12, /* Direct 16 bit zero extended */
	R_X86_64_PC16 = 13, /* 16 bit sign extended pc relative */
	R_X86_64_8 = 14, /* Direct 8 bit sign extended  */
	R_X86_64_PC8 = 15, /* 8 bit sign extended pc relative */
	R_X86_64_DTPMOD64 = 16, /* ID of module containing symbol */
	R_X86_64_DTPOFF64 = 17, /* Offset in module's TLS block */
	R_X86_64_TPOFF64 = 18, /* Offset in initial TLS block */
	R_X86_64_TLSGD = 19, /* 32 bit signed PC relative offset
						  to two GOT entries for GD symbol */
	R_X86_64_TLSLD = 20, /* 32 bit signed PC relative offset
						  to two GOT entries for LD symbol */
	R_X86_64_DTPOFF32 = 21, /* Offset in TLS block */
	R_X86_64_GOTTPOFF = 22, /* 32 bit signed PC relative offset
						  to GOT entry for IE symbol */
	R_X86_64_TPOFF32 = 23, /* Offset in initial TLS block */
	R_X86_64_PC64 = 24, /* PC relative 64 bit */
	R_X86_64_GOTOFF64 = 25, /* 64 bit offset to GOT */
	R_X86_64_GOTPC32 = 26, /* 32 bit signed pc relative
							  offset to GOT */
	R_X86_64_GOT64 = 27, /* 64-bit GOT entry offset */
	R_X86_64_GOTPCREL64 = 28, /* 64-bit PC relative offset
						  to GOT entry */
	R_X86_64_GOTPC64 = 29, /* 64-bit PC relative offset to GOT */
	R_X86_64_GOTPLT64 = 30, /* like GOT64, says PLT entry needed */
	R_X86_64_PLTOFF64 = 31, /* 64-bit GOT relative offset
						  to PLT entry */
	R_X86_64_SIZE32 = 32, /* Size of symbol plus 32-bit addend */
	R_X86_64_SIZE64 = 33, /* Size of symbol plus 64-bit addend */
	R_X86_64_GOTPC32_TLSDESC = 34, /* GOT offset for TLS descriptor.  */
	R_X86_64_TLSDESC_CALL = 35, /* Marker for call through TLS
						  descriptor.  */
	R_X86_64_TLSDESC = 36, /* TLS descriptor.  */
	R_X86_64_IRELATIVE = 37, /* Adjust indirectly by program base */
	R_X86_64_RELATIVE64 = 38, /* 64-bit adjust by program base */
	/* 39 Reserved was R_X86_64_PC32_BND */
	/* 40 Reserved was R_X86_64_PLT32_BND */
	R_X86_64_GOTPCRELX = 41, /* Load from 32 bit signed pc relative
						  offset to GOT entry without REX
						  prefix, relaxable.  */
	R_X86_64_REX_GOTPCRELX = 42, /* Load from 32 bit signed pc relative
						  offset to GOT entry with REX
					  prefix,   relaxable.  */
	R_X86_64_NUM = 43
};

// Relocation entry, without explicit addend.
struct Elf32_Rel {
	Elf32_Addr
	    r_offset; // Location (file byte offset, or program virtual addr)
	Elf32_Word r_info; // Symbol table index and type of relocation to apply

	// These accessors and mutators correspond to the ELF32_R_SYM,
	// ELF32_R_TYPE, and ELF32_R_INFO macros defined in the ELF
	// specification:
	// Elf32_Word getSymbol() const { return (r_info >> 8); }
	// unsigned char getType() const
	// {
	// 	return (unsigned char)(r_info & 0x0ff);
	// }
	// void setSymbol(Elf32_Word s) { setSymbolAndType(s, getType()); }
	// void setType(unsigned char t) { setSymbolAndType(getSymbol(), t); }
	// void setSymbolAndType(Elf32_Word s, unsigned char t)
	// {
	// 	r_info = (s << 8) + t;
	// }
};

// Relocation entry with explicit addend.
struct Elf32_Rela {
	Elf32_Addr
	    r_offset; // Location (file byte offset, or program virtual addr)
	Elf32_Word r_info; // Symbol table index and type of relocation to apply
	Elf32_Sword
	    r_addend; // Compute value for relocatable field by adding this

	// These accessors and mutators correspond to the ELF32_R_SYM,
	// ELF32_R_TYPE, and ELF32_R_INFO macros defined in the ELF
	// specification:
	// Elf32_Word getSymbol() const { return (r_info >> 8); }
	// unsigned char getType() const
	// {
	// 	return (unsigned char)(r_info & 0x0ff);
	// }
	// void setSymbol(Elf32_Word s) { setSymbolAndType(s, getType()); }
	// void setType(unsigned char t) { setSymbolAndType(getSymbol(), t); }
	// void setSymbolAndType(Elf32_Word s, unsigned char t)
	// {
	// 	r_info = (s << 8) + t;
	// }
};

// Relocation entry without explicit addend or info (relative relocations only).
typedef Elf32_Word Elf32_Relr; // offset/bitmap for relative relocations

// Relocation entry, without explicit addend.
struct Elf64_Rel {
	Elf64_Addr
	    r_offset; // Location (file byte offset, or program virtual addr).
	Elf64_Xword
	    r_info; // Symbol table index and type of relocation to apply.

	// These accessors and mutators correspond to the ELF64_R_SYM,
	// ELF64_R_TYPE, and ELF64_R_INFO macros defined in the ELF
	// specification:
	// Elf64_Word getSymbol() const { return (r_info >> 32); }
	// Elf64_Word getType() const
	// {
	// 	return (Elf64_Word)(r_info & 0xffffffffL);
	// }
	// void setSymbol(Elf64_Word s) { setSymbolAndType(s, getType()); }
	// void setType(Elf64_Word t) { setSymbolAndType(getSymbol(), t); }
	// void setSymbolAndType(Elf64_Word s, Elf64_Word t)
	// {
	// 	r_info = ((Elf64_Xword)s << 32) + (t & 0xffffffffL);
	// }
};

// Relocation entry with explicit addend.
struct Elf64_Rela {
	Elf64_Addr
	    r_offset; // Location (file byte offset, or program virtual addr).
	Elf64_Xword
	    r_info; // Symbol table index and type of relocation to apply.
	Elf64_Sxword
	    r_addend; // Compute value for relocatable field by adding this.

	// These accessors and mutators correspond to the ELF64_R_SYM,
	// ELF64_R_TYPE, and ELF64_R_INFO macros defined in the ELF
	// specification:
	// Elf64_Word getSymbol() const { return (r_info >> 32); }
	// Elf64_Word getType() const
	// {
	// 	return (Elf64_Word)(r_info & 0xffffffffL);
	// }
	// void setSymbol(Elf64_Word s) { setSymbolAndType(s, getType()); }
	// void setType(Elf64_Word t) { setSymbolAndType(getSymbol(), t); }
	// void setSymbolAndType(Elf64_Word s, Elf64_Word t)
	// {
	// 	r_info = ((Elf64_Xword)s << 32) + (t & 0xffffffffL);
	// }
};

extern Elf64_Word rela_get_type(struct Elf64_Rela *rela);

// Relocation entry without explicit addend or info (relative relocations only).
typedef Elf64_Xword Elf64_Relr; // offset/bitmap for relative relocations

// Program header for ELF32.
struct Elf32_Phdr {
	Elf32_Word p_type; // Type of segment
	Elf32_Off p_offset; // File offset where segment is located, in bytes
	Elf32_Addr p_vaddr; // Virtual address of beginning of segment
	Elf32_Addr
	    p_paddr; // Physical address of beginning of segment (OS-specific)
	Elf32_Word
	    p_filesz; // Num. of bytes in file image of segment (may be zero)
	Elf32_Word
	    p_memsz; // Num. of bytes in mem image of segment (may be zero)
	Elf32_Word p_flags; // Segment flags
	Elf32_Word p_align; // Segment alignment constraint
};

// Program header for ELF64.
struct Elf64_Phdr {
	Elf64_Word p_type; // Type of segment
	Elf64_Word p_flags; // Segment flags
	Elf64_Off p_offset; // File offset where segment is located, in bytes
	Elf64_Addr p_vaddr; // Virtual address of beginning of segment
	Elf64_Addr
	    p_paddr; // Physical addr of beginning of segment (OS-specific)
	Elf64_Xword
	    p_filesz; // Num. of bytes in file image of segment (may be zero)
	Elf64_Xword
	    p_memsz; // Num. of bytes in mem image of segment (may be zero)
	Elf64_Xword p_align; // Segment alignment constraint
};

// Segment types.
enum {
	PT_NULL = 0, // Unused segment.
	PT_LOAD = 1, // Loadable segment.
	PT_DYNAMIC = 2, // Dynamic linking information.
	PT_INTERP = 3, // Interpreter pathname.
	PT_NOTE = 4, // Auxiliary information.
	PT_SHLIB = 5, // Reserved.
	PT_PHDR = 6, // The program header table itself.
	PT_TLS = 7, // The thread-local storage template.
	PT_LOOS = 0x60000000, // Lowest operating system-specific pt entry type.
	PT_HIOS = 0x6fffffff, // Highest operating system-specific pt entry type.
	PT_LOPROC = 0x70000000, // Lowest processor-specific program hdr entry type.
	PT_HIPROC = 0x7fffffff, // Highest processor-specific program hdr entry type.

	// x86-64 program header types.
	// These all contain stack unwind tables.
	PT_GNU_EH_FRAME = 0x6474e550,
	PT_SUNW_EH_FRAME = 0x6474e550,
	PT_SUNW_UNWIND = 0x6464e550,

	PT_GNU_STACK = 0x6474e551, // Indicates stack executability.
	PT_GNU_RELRO = 0x6474e552, // Read-only after relocation.
	PT_GNU_PROPERTY = 0x6474e553, // .note.gnu.property notes sections.

	PT_OPENBSD_RANDOMIZE = 0x65a3dbe6, // Fill with random data.
	PT_OPENBSD_WXNEEDED = 0x65a3dbe7, // Program does W^X violations.
	PT_OPENBSD_BOOTDATA = 0x65a41be6, // Section for boot arguments.

	// ARM program header types.
	PT_ARM_ARCHEXT = 0x70000000, // Platform architecture compatibility info
	// These all contain stack unwind tables.
	PT_ARM_EXIDX = 0x70000001,
	PT_ARM_UNWIND = 0x70000001,

	// MIPS program header types.
	PT_MIPS_REGINFO = 0x70000000, // Register usage information.
	PT_MIPS_RTPROC = 0x70000001, // Runtime procedure table.
	PT_MIPS_OPTIONS = 0x70000002, // Options segment.
	PT_MIPS_ABIFLAGS = 0x70000003, // Abiflags segment.
};

// Segment flag bits.
enum {
	PF_X = 1, // Execute
	PF_W = 2, // Write
	PF_R = 4, // Read
	PF_MASKOS = 0x0ff00000, // Bits for operating system-specific semantics.
	PF_MASKPROC = 0xf0000000 // Bits for processor-specific semantics.
};
enum {
	DT_NULL = 0,
	DT_NEEDED = 1,
	DT_PLTRELSZ = 2,
	DT_PLTGOT = 3,
	DT_HASH = 4,
	DT_STRTAB = 5,
	DT_SYMTAB = 6,
	DT_RELA = 7,
	DT_RELASZ = 8,
	DT_RELAENT = 9,
	DT_STRSZ = 11,
	DT_SYMENT = 11,
	DT_INIT = 12,
	DT_FINI = 13,
	DT_SONAME = 14,
	DT_RPATH = 15,
	DT_SYMBOLIC = 16,
	DT_REL = 17,
	DT_RELSZ = 18,
	DT_RELENT = 19,
	DT_PLTREL = 20,
	DT_DEBUG = 21,
	DT_TEXTREL = 22,
	DT_JMPREL = 23,
	DT_INIT_ARRAY = 25,
	DT_FINI_ARRAY = 26,
	DT_INIT_ARRAYSZ = 27,
	DT_FINI_ARRAYSZ = 28,
	DT_ENCODING = 32,
	DT_PREINIT_ARRAY = 32,
	OLD_DT_LOOS = 0x60000000,
	DT_LOOS = 0x6000000d,
	DT_HIOS = 0x6ffff000,
	DT_VALRNGLO = 0x6ffffd00,
	DT_VALRNGHI = 0x6ffffdff,
	DT_ADDRRNGLO = 0x6ffffe00,
	DT_ADDRRNGHI = 0x6ffffeff,
	DT_VERSYM = 0x6ffffff0,
	DT_RELACOUNT = 0x6ffffff9,
	DT_RELCOUNT = 0x6ffffffa,
	DT_FLAGS_1 = 0x6ffffffb,
	DT_VERDEF = 0x6ffffffc,
	DT_GNU_HASH = 0x6ffffef5,
	DT_VERDEFNUM = 0x6ffffffd,
	DT_VERNEED = 0x6ffffffe,
	DT_VERNEEDNUM = 0x6fffffff,
	OLD_DT_HIOS = 0x6fffffff,
	DT_LOPROC = 0x70000000,
	DT_HIPROC = 0x7fffffff
};

// Dynamic table entry for ELF32.
struct Elf32_Dyn {
	Elf32_Sword d_tag; // Type of dynamic table entry.
	union {
		Elf32_Word d_val; // Integer value of entry.
		Elf32_Addr d_ptr; // Pointer value of entry.
	} d_un;
};

// Dynamic table entry for ELF64.
struct Elf64_Dyn {
	Elf64_Sxword d_tag; // Type of dynamic table entry.
	union {
		Elf64_Xword d_val; // Integer value of entry.
		Elf64_Addr d_ptr; // Pointer value of entry.
	} d_un;
};

// DT_FLAGS values.
enum {
	DF_ORIGIN = 0x01, // The object may reference $ORIGIN.
	DF_SYMBOLIC = 0x02, // Search the shared lib before searching the exe.
	DF_TEXTREL = 0x04, // Relocations may modify a non-writable segment.
	DF_BIND_NOW = 0x08, // Process all relocations on load.
	DF_STATIC_TLS = 0x10 // Reject attempts to load dynamically.
};

// State flags selectable in the `d_un.d_val' element of the DT_FLAGS_1 entry.
enum {
	DF_1_NOW = 0x00000001, // Set RTLD_NOW for this object.
	DF_1_GLOBAL = 0x00000002, // Set RTLD_GLOBAL for this object.
	DF_1_GROUP = 0x00000004, // Set RTLD_GROUP for this object.
	DF_1_NODELETE = 0x00000008, // Set RTLD_NODELETE for this object.
	DF_1_LOADFLTR = 0x00000010, // Trigger filtee loading at runtime.
	DF_1_INITFIRST = 0x00000020, // Set RTLD_INITFIRST for this object.
	DF_1_NOOPEN = 0x00000040, // Set RTLD_NOOPEN for this object.
	DF_1_ORIGIN = 0x00000080, // $ORIGIN must be handled.
	DF_1_DIRECT = 0x00000100, // Direct binding enabled.
	DF_1_TRANS = 0x00000200,
	DF_1_INTERPOSE = 0x00000400, // Object is used to interpose.
	DF_1_NODEFLIB = 0x00000800, // Ignore default lib search path.
	DF_1_NODUMP = 0x00001000, // Object can't be dldump'ed.
	DF_1_CONFALT = 0x00002000, // Configuration alternative created.
	DF_1_ENDFILTEE = 0x00004000, // Filtee terminates filters search.
	DF_1_DISPRELDNE = 0x00008000, // Disp reloc applied at build time.
	DF_1_DISPRELPND = 0x00010000, // Disp reloc applied at run-time.
	DF_1_NODIRECT = 0x00020000, // Object has no-direct binding.
	DF_1_IGNMULDEF = 0x00040000,
	DF_1_NOKSYMS = 0x00080000,
	DF_1_NOHDR = 0x00100000,
	DF_1_EDITED = 0x00200000, // Object is modified after built.
	DF_1_NORELOC = 0x00400000,
	DF_1_SYMINTPOSE = 0x00800000, // Object has individual interposers.
	DF_1_GLOBAUDIT = 0x01000000, // Global auditing required.
	DF_1_SINGLETON = 0x02000000, // Singleton symbols are used.
	DF_1_PIE = 0x08000000, // Object is a position-independent executable.
};

// DT_MIPS_FLAGS values.
enum {
	RHF_NONE = 0x00000000, // No flags.
	RHF_QUICKSTART = 0x00000001, // Uses shortcut pointers.
	RHF_NOTPOT = 0x00000002, // Hash size is not a power of two.
	RHS_NO_LIBRARY_REPLACEMENT = 0x00000004, // Ignore LD_LIBRARY_PATH.
	RHF_NO_MOVE = 0x00000008, // DSO address may not be relocated.
	RHF_SGI_ONLY = 0x00000010, // SGI specific features.
	RHF_GUARANTEE_INIT = 0x00000020, // Guarantee that .init will finish
	// executing before any non-init
	// code in DSO is called.
	RHF_DELTA_C_PLUS_PLUS = 0x00000040, // Contains Delta C++ code.
	RHF_GUARANTEE_START_INIT = 0x00000080, // Guarantee that .init will start
	// executing before any non-init
	// code in DSO is called.
	RHF_PIXIE = 0x00000100, // Generated by pixie.
	RHF_DEFAULT_DELAY_LOAD = 0x00000200, // Delay-load DSO by default.
	RHF_REQUICKSTART = 0x00000400, // Object may be requickstarted
	RHF_REQUICKSTARTED = 0x00000800, // Object has been requickstarted
	RHF_CORD = 0x00001000, // Generated by cord.
	RHF_NO_UNRES_UNDEF = 0x00002000, // Object contains no unresolved
	// undef symbols.
	RHF_RLD_ORDER_SAFE = 0x00004000 // Symbol table is in a safe order.
};

// ElfXX_VerDef structure version (GNU versioning)
enum { VER_DEF_NONE = 0,
	VER_DEF_CURRENT = 1 };

// VerDef Flags (ElfXX_VerDef::vd_flags)
enum { VER_FLG_BASE = 0x1,
	VER_FLG_WEAK = 0x2,
	VER_FLG_INFO = 0x4 };

// Special constants for the version table. (SHT_GNU_versym/.gnu.version)
enum {
	VER_NDX_LOCAL = 0, // Unversioned local symbol
	VER_NDX_GLOBAL = 1, // Unversioned global symbol
	VERSYM_VERSION = 0x7fff, // Version Index mask
	VERSYM_HIDDEN = 0x8000 // Hidden bit (non-default version)
};

// ElfXX_VerNeed structure version (GNU versioning)
enum { VER_NEED_NONE = 0,
	VER_NEED_CURRENT = 1 };

// SHT_NOTE section types
enum {
	NT_FREEBSD_THRMISC = 7,
	NT_FREEBSD_PROCSTAT_PROC = 8,
	NT_FREEBSD_PROCSTAT_FILES = 9,
	NT_FREEBSD_PROCSTAT_VMMAP = 10,
	NT_FREEBSD_PROCSTAT_GROUPS = 11,
	NT_FREEBSD_PROCSTAT_UMASK = 12,
	NT_FREEBSD_PROCSTAT_RLIMIT = 13,
	NT_FREEBSD_PROCSTAT_OSREL = 14,
	NT_FREEBSD_PROCSTAT_PSSTRINGS = 15,
	NT_FREEBSD_PROCSTAT_AUXV = 16,
};

// Generic note types
enum {
	NT_VERSION = 1,
	NT_ARCH = 2,
	NT_GNU_BUILD_ATTRIBUTE_OPEN = 0x100,
	NT_GNU_BUILD_ATTRIBUTE_FUNC = 0x101,
};

// Core note types
enum {
	NT_PRSTATUS = 1,
	NT_FPREGSET = 2,
	NT_PRPSINFO = 3,
	NT_TASKSTRUCT = 4,
	NT_AUXV = 6,
	NT_PSTATUS = 10,
	NT_FPREGS = 12,
	NT_PSINFO = 13,
	NT_LWPSTATUS = 16,
	NT_LWPSINFO = 17,
	NT_WIN32PSTATUS = 18,

	NT_PPC_VMX = 0x100,
	NT_PPC_VSX = 0x102,
	NT_PPC_TAR = 0x103,
	NT_PPC_PPR = 0x104,
	NT_PPC_DSCR = 0x105,
	NT_PPC_EBB = 0x106,
	NT_PPC_PMU = 0x107,
	NT_PPC_TM_CGPR = 0x108,
	NT_PPC_TM_CFPR = 0x109,
	NT_PPC_TM_CVMX = 0x10a,
	NT_PPC_TM_CVSX = 0x10b,
	NT_PPC_TM_SPR = 0x10c,
	NT_PPC_TM_CTAR = 0x10d,
	NT_PPC_TM_CPPR = 0x10e,
	NT_PPC_TM_CDSCR = 0x10f,

	NT_386_TLS = 0x200,
	NT_386_IOPERM = 0x201,
	NT_X86_XSTATE = 0x202,

	NT_S390_HIGH_GPRS = 0x300,
	NT_S390_TIMER = 0x301,
	NT_S390_TODCMP = 0x302,
	NT_S390_TODPREG = 0x303,
	NT_S390_CTRS = 0x304,
	NT_S390_PREFIX = 0x305,
	NT_S390_LAST_BREAK = 0x306,
	NT_S390_SYSTEM_CALL = 0x307,
	NT_S390_TDB = 0x308,
	NT_S390_VXRS_LOW = 0x309,
	NT_S390_VXRS_HIGH = 0x30a,
	NT_S390_GS_CB = 0x30b,
	NT_S390_GS_BC = 0x30c,

	NT_ARM_VFP = 0x400,
	NT_ARM_TLS = 0x401,
	NT_ARM_HW_BREAK = 0x402,
	NT_ARM_HW_WATCH = 0x403,
	NT_ARM_SVE = 0x405,
	NT_ARM_PAC_MASK = 0x406,

	NT_FILE = 0x46494c45,
	NT_PRXFPREG = 0x46e62b7f,
	NT_SIGINFO = 0x53494749,
};

// LLVM-specific notes.
enum {
	NT_LLVM_HWASAN_GLOBALS = 3,
};

// GNU note types
enum {
	NT_GNU_ABI_TAG = 1,
	NT_GNU_HWCAP = 2,
	NT_GNU_BUILD_ID = 3,
	NT_GNU_GOLD_VERSION = 4,
	NT_GNU_PROPERTY_TYPE_0 = 5,
};

// Property types used in GNU_PROPERTY_TYPE_0 notes.
enum {
	GNU_PROPERTY_STACK_SIZE = 1,
	GNU_PROPERTY_NO_COPY_ON_PROTECTED = 2,
	GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000,
	GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002,
	GNU_PROPERTY_X86_ISA_1_NEEDED = 0xc0008000,
	GNU_PROPERTY_X86_FEATURE_2_NEEDED = 0xc0008001,
	GNU_PROPERTY_X86_ISA_1_USED = 0xc0010000,
	GNU_PROPERTY_X86_FEATURE_2_USED = 0xc0010001,
};

// aarch64 processor feature bits.
enum {
	GNU_PROPERTY_AARCH64_FEATURE_1_BTI = 1 << 0,
	GNU_PROPERTY_AARCH64_FEATURE_1_PAC = 1 << 1,
};

// x86 processor feature bits.
enum {
	GNU_PROPERTY_X86_FEATURE_1_IBT = 1 << 0,
	GNU_PROPERTY_X86_FEATURE_1_SHSTK = 1 << 1,

	GNU_PROPERTY_X86_ISA_1_CMOV = 1 << 0,
	GNU_PROPERTY_X86_ISA_1_SSE = 1 << 1,
	GNU_PROPERTY_X86_ISA_1_SSE2 = 1 << 2,
	GNU_PROPERTY_X86_ISA_1_SSE3 = 1 << 3,
	GNU_PROPERTY_X86_ISA_1_SSSE3 = 1 << 4,
	GNU_PROPERTY_X86_ISA_1_SSE4_1 = 1 << 5,
	GNU_PROPERTY_X86_ISA_1_SSE4_2 = 1 << 6,
	GNU_PROPERTY_X86_ISA_1_AVX = 1 << 7,
	GNU_PROPERTY_X86_ISA_1_AVX2 = 1 << 8,
	GNU_PROPERTY_X86_ISA_1_FMA = 1 << 9,
	GNU_PROPERTY_X86_ISA_1_AVX512F = 1 << 10,
	GNU_PROPERTY_X86_ISA_1_AVX512CD = 1 << 11,
	GNU_PROPERTY_X86_ISA_1_AVX512ER = 1 << 12,
	GNU_PROPERTY_X86_ISA_1_AVX512PF = 1 << 13,
	GNU_PROPERTY_X86_ISA_1_AVX512VL = 1 << 14,
	GNU_PROPERTY_X86_ISA_1_AVX512DQ = 1 << 15,
	GNU_PROPERTY_X86_ISA_1_AVX512BW = 1 << 16,
	GNU_PROPERTY_X86_ISA_1_AVX512_4FMAPS = 1 << 17,
	GNU_PROPERTY_X86_ISA_1_AVX512_4VNNIW = 1 << 18,
	GNU_PROPERTY_X86_ISA_1_AVX512_BITALG = 1 << 19,
	GNU_PROPERTY_X86_ISA_1_AVX512_IFMA = 1 << 20,
	GNU_PROPERTY_X86_ISA_1_AVX512_VBMI = 1 << 21,
	GNU_PROPERTY_X86_ISA_1_AVX512_VBMI2 = 1 << 22,
	GNU_PROPERTY_X86_ISA_1_AVX512_VNNI = 1 << 23,

	GNU_PROPERTY_X86_FEATURE_2_X86 = 1 << 0,
	GNU_PROPERTY_X86_FEATURE_2_X87 = 1 << 1,
	GNU_PROPERTY_X86_FEATURE_2_MMX = 1 << 2,
	GNU_PROPERTY_X86_FEATURE_2_XMM = 1 << 3,
	GNU_PROPERTY_X86_FEATURE_2_YMM = 1 << 4,
	GNU_PROPERTY_X86_FEATURE_2_ZMM = 1 << 5,
	GNU_PROPERTY_X86_FEATURE_2_FXSR = 1 << 6,
	GNU_PROPERTY_X86_FEATURE_2_XSAVE = 1 << 7,
	GNU_PROPERTY_X86_FEATURE_2_XSAVEOPT = 1 << 8,
	GNU_PROPERTY_X86_FEATURE_2_XSAVEC = 1 << 9,
};

// AMDGPU-specific section indices.
enum {
	SHN_AMDGPU_LDS = 0xff00, // Variable in LDS; symbol encoded like SHN_COMMON
};

// AMD specific notes. (Code Object V2)
enum {
	// Note types with values between 0 and 9 (inclusive) are reserved.
	NT_AMD_AMDGPU_HSA_METADATA = 10,
	NT_AMD_AMDGPU_ISA = 11,
	NT_AMD_AMDGPU_PAL_METADATA = 12
};

// AMDGPU specific notes. (Code Object V3)
enum {
	// Note types with values between 0 and 31 (inclusive) are reserved.
	NT_AMDGPU_METADATA = 32
};

enum {
	GNU_ABI_TAG_LINUX = 0,
	GNU_ABI_TAG_HURD = 1,
	GNU_ABI_TAG_SOLARIS = 2,
	GNU_ABI_TAG_FREEBSD = 3,
	GNU_ABI_TAG_NETBSD = 4,
	GNU_ABI_TAG_SYLLABLE = 5,
	GNU_ABI_TAG_NACL = 6,
};

// Android packed relocation group flags.
enum {
	RELOCATION_GROUPED_BY_INFO_FLAG = 1,
	RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2,
	RELOCATION_GROUPED_BY_ADDEND_FLAG = 4,
	RELOCATION_GROUP_HAS_ADDEND_FLAG = 8,
};

// Compressed section header for ELF32.
struct Elf32_Chdr {
	Elf32_Word ch_type;
	Elf32_Word ch_size;
	Elf32_Word ch_addralign;
};

// Compressed section header for ELF64.
struct Elf64_Chdr {
	Elf64_Word ch_type;
	Elf64_Word ch_reserved;
	Elf64_Xword ch_size;
	Elf64_Xword ch_addralign;
};

// Node header for ELF32.
struct Elf32_Nhdr {
	Elf32_Word n_namesz;
	Elf32_Word n_descsz;
	Elf32_Word n_type;
};

// Node header for ELF64.
struct Elf64_Nhdr {
	Elf64_Word n_namesz;
	Elf64_Word n_descsz;
	Elf64_Word n_type;
};

// Legal values for ch_type field of compressed section header.
enum {
	ELFCOMPRESS_ZLIB = 1, // ZLIB/DEFLATE algorithm.
	ELFCOMPRESS_LOOS = 0x60000000, // Start of OS-specific.
	ELFCOMPRESS_HIOS = 0x6fffffff, // End of OS-specific.
	ELFCOMPRESS_LOPROC = 0x70000000, // Start of processor-specific.
	ELFCOMPRESS_HIPROC = 0x7fffffff // End of processor-specific.
};
