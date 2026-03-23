// Adapted from HunterRuntime/test/src/main/cpp/dlfc/elf_util.cpp
// Original by swift (2019). Adapted for AnyCheck detection use.
// Logging dependencies replaced with android/log.h macros.

#include "hunter_elf.h"

#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <android/log.h>

#define AC_ELF_TAG "anycheck_elf"
#define AC_LOGE(...) __android_log_print(ANDROID_LOG_ERROR,  AC_ELF_TAG, __VA_ARGS__)
#define AC_LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,  AC_ELF_TAG, __VA_ARGS__)

namespace anycheck {
namespace elf {

ElfImg::ElfImg(const char *elf_path) {
    elf_path_ = elf_path;

    int fd = open(elf_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        AC_LOGE("ElfImg: failed to open %s", elf_path);
        return;
    }

    size_ = lseek(fd, 0, SEEK_END);
    if (size_ <= 0) {
        AC_LOGE("ElfImg: lseek failed for %s", elf_path);
        close(fd);
        return;
    }

    header_ = reinterpret_cast<AC_Elf_Ehdr *>(
        mmap(nullptr, static_cast<size_t>(size_), PROT_READ, MAP_SHARED, fd, 0));
    close(fd);

    if (header_ == MAP_FAILED) {
        AC_LOGE("ElfImg: mmap failed for %s", elf_path);
        header_ = nullptr;
        return;
    }

    section_header_ = reinterpret_cast<AC_Elf_Shdr *>(
        reinterpret_cast<size_t>(header_) + header_->e_shoff);

    size_t shoff = reinterpret_cast<size_t>(section_header_);
    char *section_str = reinterpret_cast<char *>(
        section_header_[header_->e_shstrndx].sh_offset +
        reinterpret_cast<size_t>(header_));

    for (int i = 0; i < header_->e_shnum; i++, shoff += header_->e_shentsize) {
        auto *sh = reinterpret_cast<AC_Elf_Shdr *>(shoff);
        char *sname = sh->sh_name + section_str;
        AC_Elf_Off entsize = sh->sh_entsize;

        switch (sh->sh_type) {
            case SHT_DYNSYM:
                if (bias_ == -4396) {
                    dynsym_        = sh;
                    dynsym_offset_ = sh->sh_offset;
                    dynsym_size_   = sh->sh_size;
                    dynsym_count_  = (entsize > 0) ? (dynsym_size_ / entsize) : 0;
                    dynsym_start_  = reinterpret_cast<AC_Elf_Sym *>(
                        reinterpret_cast<size_t>(header_) + dynsym_offset_);
                }
                break;
            case SHT_SYMTAB:
                if (strcmp(sname, ".symtab") == 0) {
                    symtab_        = sh;
                    symtab_offset_ = sh->sh_offset;
                    symtab_size_   = sh->sh_size;
                    symtab_count_  = (entsize > 0) ? (symtab_size_ / entsize) : 0;
                    symtab_start_  = reinterpret_cast<AC_Elf_Sym *>(
                        reinterpret_cast<size_t>(header_) + symtab_offset_);
                }
                break;
            case SHT_STRTAB:
                if (bias_ == -4396) {
                    strtab_          = sh;
                    symstr_offset_   = sh->sh_offset;
                    strtab_start_    = reinterpret_cast<AC_Elf_Sym *>(
                        reinterpret_cast<size_t>(header_) + symstr_offset_);
                }
                if (strcmp(sname, ".strtab") == 0) {
                    symstr_offset_for_symtab_ = sh->sh_offset;
                }
                break;
            case SHT_PROGBITS:
                if (strtab_ == nullptr || dynsym_ == nullptr) break;
                if (bias_ == -4396) {
                    bias_ = static_cast<off_t>(sh->sh_addr) -
                            static_cast<off_t>(sh->sh_offset);
                }
                break;
            default:
                break;
        }
    }

    base_in_ram_ = getModuleBase(elf_path);
}

ElfImg::~ElfImg() {
    if (buffer_) {
        free(buffer_);
        buffer_ = nullptr;
    }
    if (header_) {
        munmap(header_, static_cast<size_t>(size_));
        header_ = nullptr;
    }
}

AC_Elf_Addr ElfImg::getSymOffset(const char *name) {
    // Search .dynsym first (exported symbols).
    if (dynsym_start_ != nullptr && strtab_start_ != nullptr) {
        auto *sym     = dynsym_start_;
        auto *strings = reinterpret_cast<char *>(strtab_start_);
        for (AC_Elf_Off k = 0; k < dynsym_count_; k++, sym++) {
            if (strcmp(strings + sym->st_name, name) == 0) {
                return sym->st_value;
            }
        }
    }

    // Fall back to .symtab (debug/static symbols).
    if (symtab_start_ != nullptr && symstr_offset_for_symtab_ != 0) {
        for (AC_Elf_Off i = 0; i < symtab_count_; i++) {
            unsigned int st_type = AC_ELF_ST_TYPE(symtab_start_[i].st_info);
            if (st_type == STT_FUNC && symtab_start_[i].st_size > 0) {
                auto *st_name = reinterpret_cast<char *>(
                    reinterpret_cast<size_t>(header_) +
                    symstr_offset_for_symtab_ +
                    symtab_start_[i].st_name);
                if (strcmp(st_name, name) == 0) {
                    return symtab_start_[i].st_value;
                }
            }
        }
    }
    return 0;
}

AC_Elf_Addr ElfImg::getSymAddress(const char *name) {
    AC_Elf_Addr offset = getSymOffset(name);
    if (offset > 0 && base_in_ram_ != nullptr) {
        return static_cast<AC_Elf_Addr>(
            reinterpret_cast<size_t>(base_in_ram_) + offset - bias_);
    }
    return 0;
}

void *ElfImg::getModuleBase(const char *name) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return nullptr;

    char buff[256];
    unsigned long load_addr = 0;
    bool found = false;

    while (fgets(buff, sizeof(buff), maps)) {
        if ((strstr(buff, "r-xp") || strstr(buff, "r--p")) && strstr(buff, name)) {
            if (sscanf(buff, "%lx", &load_addr) == 1) {
                found = true;
            }
            break;
        }
    }
    fclose(maps);

    if (!found) return nullptr;
    return reinterpret_cast<void *>(load_addr);
}

} // namespace elf
} // namespace anycheck
