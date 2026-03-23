// Adapted from HunterRuntime/test/src/main/cpp/dlfc/lsp_elf_util.h
// Original by swift (2019). Adapted for AnyCheck detection use.
//
// ElfImg: parse an ELF shared library from disk (mmap), scan its dynamic
// symbol table (.dynsym) and optional static symbol table (.symtab) to
// find exported or debug-only symbol addresses. Used by N10 ELF-symbol probe.

#pragma once

#include <linux/elf.h>
#include <list>
#include <string>

#if defined(__LP64__)
typedef Elf64_Ehdr AC_Elf_Ehdr;
typedef Elf64_Shdr AC_Elf_Shdr;
typedef Elf64_Addr AC_Elf_Addr;
typedef Elf64_Sym  AC_Elf_Sym;
typedef Elf64_Off  AC_Elf_Off;
#define AC_ELF_ST_TYPE ELF64_ST_TYPE
#else
typedef Elf32_Ehdr AC_Elf_Ehdr;
typedef Elf32_Shdr AC_Elf_Shdr;
typedef Elf32_Addr AC_Elf_Addr;
typedef Elf32_Sym  AC_Elf_Sym;
typedef Elf32_Off  AC_Elf_Off;
#define AC_ELF_ST_TYPE ELF32_ST_TYPE
#endif

namespace anycheck {
namespace elf {

class ElfImg {
public:
    explicit ElfImg(const char *elf_path);
    ~ElfImg();

    /** Look up a symbol by name; returns its in-memory address or 0. */
    AC_Elf_Addr getSymAddress(const char *name);

    /** Returns true if the library was successfully mapped. */
    bool valid() const { return header_ != nullptr; }

    static void *getModuleBase(const char *name);

private:
    AC_Elf_Addr getSymOffset(const char *name);

    const char *elf_path_ = nullptr;
    void       *base_in_ram_ = nullptr;
    char       *buffer_ = nullptr;
    off_t       size_ = 0;
    off_t       bias_ = -4396;

    AC_Elf_Ehdr *header_          = nullptr;
    AC_Elf_Shdr *section_header_  = nullptr;
    AC_Elf_Shdr *symtab_          = nullptr;
    AC_Elf_Shdr *strtab_          = nullptr;
    AC_Elf_Shdr *dynsym_          = nullptr;

    AC_Elf_Off   dynsym_count_    = 0;
    AC_Elf_Sym  *symtab_start_    = nullptr;
    AC_Elf_Sym  *dynsym_start_    = nullptr;
    AC_Elf_Sym  *strtab_start_    = nullptr;
    AC_Elf_Off   symtab_count_    = 0;
    AC_Elf_Off   symstr_offset_   = 0;
    AC_Elf_Off   symstr_offset_for_symtab_ = 0;
    AC_Elf_Off   symtab_offset_   = 0;
    AC_Elf_Off   dynsym_offset_   = 0;
    AC_Elf_Off   symtab_size_     = 0;
    AC_Elf_Off   dynsym_size_     = 0;
};

} // namespace elf
} // namespace anycheck
