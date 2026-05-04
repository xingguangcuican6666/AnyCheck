#include <jni.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <android/log.h>
#include <stdint.h>
#include <cerrno>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "hunter_elf.h"

#define LOG_TAG "anycheck_native"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// __NR_fstatat is not always defined in Android NDK headers; define per-arch.
#ifndef __NR_fstatat
#  if defined(__aarch64__)
#    define __NR_fstatat 79
#  elif defined(__arm__)
#    define __NR_fstatat 327
#  elif defined(__x86_64__)
#    define __NR_fstatat 262
#  elif defined(__i386__)
#    define __NR_fstatat 300
#  endif
#endif

// __NR_faccessat is not always defined in Android NDK headers; define per-arch.
#ifndef __NR_faccessat
#  if defined(__aarch64__)
#    define __NR_faccessat 48
#  elif defined(__arm__)
#    define __NR_faccessat 334
#  elif defined(__x86_64__)
#    define __NR_faccessat 269
#  elif defined(__i386__)
#    define __NR_faccessat 307
#  endif
#endif

// ---------------------------------------------------------------------------
// N1 — Raw /proc/self/maps scan
// Uses open(2)/read(2) syscalls — NOT fopen() — to resist GOT-level hooks.
// ---------------------------------------------------------------------------
static std::vector<std::string> scanMaps() {
    static const char *NEEDLES[] = {
        "lsposed", "lsplant", "liblsplant", "lspd",
        "edxposed", "libxposed-native", "liblspatch",
        "libfake-linker", nullptr
    };

    std::vector<std::string> findings;
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return findings;

    char buf[4096];
    std::string partial;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        partial += buf;
        size_t pos;
        while ((pos = partial.find('\n')) != std::string::npos) {
            std::string line = partial.substr(0, pos);
            partial = partial.substr(pos + 1);
            // The path is after the last space on the line
            size_t space = line.rfind(' ');
            std::string path = (space != std::string::npos) ? line.substr(space + 1) : line;
            size_t slash = path.rfind('/');
            std::string filename = (slash != std::string::npos) ? path.substr(slash + 1) : path;
            // Lower-case compare
            std::string fl = filename;
            for (char &c : fl) c = (char)tolower((unsigned char)c);
            for (int i = 0; NEEDLES[i] != nullptr; ++i) {
                if (fl.find(NEEDLES[i]) != std::string::npos) {
                    std::string entry = path.substr(0, 120);
                    bool dup = false;
                    for (const auto &f : findings) { if (f == entry) { dup = true; break; } }
                    if (!dup) findings.push_back(entry);
                    break;
                }
            }
        }
    }
    close(fd);
    return findings;
}

// ---------------------------------------------------------------------------
// N2 — dlopen(RTLD_NOLOAD) probe
// RTLD_NOLOAD succeeds (returns non-null) only if the library is already mapped.
// ---------------------------------------------------------------------------
static std::vector<std::string> probeDlopen() {
    static const char *TARGETS[] = {
        "liblsplant.so", "liblsposed.so",
        "libxposed-native.so", "liblspd.so", nullptr
    };

    std::vector<std::string> findings;
    for (int i = 0; TARGETS[i] != nullptr; ++i) {
        void *h = dlopen(TARGETS[i], RTLD_NOLOAD | RTLD_LAZY);
        if (h != nullptr) {
            findings.push_back(std::string("dlopen:") + TARGETS[i]);
            dlclose(h);
        }
    }
    return findings;
}

// ---------------------------------------------------------------------------
// N3 — dlsym(RTLD_DEFAULT) symbol search
// Looks for exported XposedBridge / LSPlant symbols in the global namespace.
// ---------------------------------------------------------------------------
static std::vector<std::string> probeDlsym() {
    static const char *SYMBOLS[] = {
        "xposedBridgeHandleHookedMethod",
        "Java_de_robv_android_xposed_XposedBridge_hookMethodNative",
        "_ZN7lsplant10InitializeEP7_JNIEnv",
        "_ZN7lsplant4HookEP7_JNIEnvP8_jobjectP10_jmethodIDS4_",
        nullptr
    };

    std::vector<std::string> findings;
    for (int i = 0; SYMBOLS[i] != nullptr; ++i) {
        void *sym = dlsym(RTLD_DEFAULT, SYMBOLS[i]);
        if (sym != nullptr) {
            findings.push_back(std::string("dlsym:") + SYMBOLS[i]);
        }
    }
    return findings;
}

// ---------------------------------------------------------------------------
// N4 — stat() path probe
// stat() on known LSPosed/Riru/Zygisk paths.
// ---------------------------------------------------------------------------
static std::vector<std::string> probePaths() {
    static const char *PATHS[] = {
        "/data/misc/lspd",
        "/data/misc/lspd/config.json",
        "/data/adb/lspd",
        "/data/adb/modules/zygisk_lsposed",
        "/data/adb/modules/riru_lsposed",
        "/data/adb/modules/lsposed",
        nullptr
    };

    std::vector<std::string> findings;
    struct stat st{};
    for (int i = 0; PATHS[i] != nullptr; ++i) {
        if (stat(PATHS[i], &st) == 0) {
            findings.push_back(std::string("stat:") + PATHS[i]);
        }
    }
    return findings;
}

// ---------------------------------------------------------------------------
// N5 — ro.dalvik.vm.native.bridge system property
// The Riru variant of LSPosed sets this to its own loader library name.
// ---------------------------------------------------------------------------
static std::string probeNativeBridge() {
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.dalvik.vm.native.bridge", value);
    if (value[0] != '\0' && strcmp(value, "0") != 0) {
        return std::string("native.bridge=") + value;
    }
    return {};
}

// ---------------------------------------------------------------------------
// N6 — /proc/self/smaps Private_Dirty probe
// LSPlant patches libc.so / libart.so pages, leaving non-zero Private_Dirty
// on r-xp (executable) segments of those libraries.
// ---------------------------------------------------------------------------
static std::vector<std::string> probeSmaps() {
    std::vector<std::string> findings;
    int fd = open("/proc/self/smaps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return findings;

    char buf[8192];
    std::string partial;
    ssize_t n;
    bool inTarget = false;
    std::string currentLib;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        partial += buf;
        size_t pos;
        while ((pos = partial.find('\n')) != std::string::npos) {
            std::string line = partial.substr(0, pos);
            partial = partial.substr(pos + 1);
            // Detect a mapping header line (contains memory address range)
            if (line.size() > 20 && line[8] == '-') {
                inTarget = false;
                currentLib.clear();
                // Check if it's an executable mapping of libart/libc
                if (line.find("r-xp") != std::string::npos) {
                    size_t sp = line.rfind(' ');
                    std::string path = (sp != std::string::npos) ? line.substr(sp + 1) : "";
                    size_t sl = path.rfind('/');
                    std::string fname = (sl != std::string::npos) ? path.substr(sl + 1) : path;
                    if (fname == "libart.so" || fname == "libc.so") {
                        inTarget = true;
                        currentLib = fname;
                    }
                }
            } else if (inTarget && line.find("Private_Dirty:") == 0) {
                // Parse the kB value
                size_t colon = line.find(':');
                if (colon != std::string::npos) {
                    std::string valStr = line.substr(colon + 1);
                    // trim whitespace
                    size_t start = valStr.find_first_not_of(" \t");
                    if (start != std::string::npos) valStr = valStr.substr(start);
                    size_t end = valStr.find(' ');
                    if (end != std::string::npos) valStr = valStr.substr(0, end);
                    int kbVal = 0;
                    try { kbVal = std::stoi(valStr); } catch (...) {}
                    if (kbVal > 0) {
                        std::string entry = "smaps_dirty:" + currentLib + "=" + valStr + "kB";
                        bool dup = false;
                        for (const auto &f : findings) { if (f == entry) { dup = true; break; } }
                        if (!dup) findings.push_back(entry);
                    }
                }
                inTarget = false;
            }
        }
    }
    close(fd);
    return findings;
}

// ---------------------------------------------------------------------------
// N7 — Own ODEX binary scan (via raw syscalls)
// Locates this app's own base.odex in /proc/self/maps and scans it for
// LSPosed / hooking-framework string markers.  Uses open(2)/read(2) so the
// scan cannot be intercepted by GOT-level hooks on fopen/fread.
// ---------------------------------------------------------------------------
static std::vector<std::string> scanOwnOdex() {
    // Step 1: find our own base.odex path from /proc/self/maps.
    std::string odexPath;
    {
        int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return {};
        char buf[4096];
        std::string partial;
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf) - 1)) > 0 && odexPath.empty()) {
            buf[n] = '\0';
            partial += buf;
            size_t pos;
            while ((pos = partial.find('\n')) != std::string::npos) {
                std::string line = partial.substr(0, pos);
                partial = partial.substr(pos + 1);
                size_t sp = line.rfind(' ');
                if (sp == std::string::npos) continue;
                std::string path = line.substr(sp + 1);
                // Pick the first entry whose path ends with "base.odex".
                // This is this app's own compiled-code file.
                const std::string suffix = "base.odex";
                if (path.size() >= suffix.size() &&
                    path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0) {
                    odexPath = path;
                    break;
                }
            }
        }
        close(fd);
    }
    if (odexPath.empty()) return {};

    // Step 2: scan the ODEX file in chunks, searching for hook-framework markers.
    static const char *MARKERS[] = {
        "lsposed", "lsplant", "liblsplant", "lspd",
        "edxposed", "xposedbridge", "XposedBridge",
        "de.robv.android.xposed",
        "dobby", "sandhook", "pine",
        nullptr
    };

    std::vector<std::string> findings;
    int fd = open(odexPath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};

    // Use a sliding-window read to catch markers that span chunk boundaries.
    // The overlap is 64 bytes — larger than the longest marker.
    const size_t OVERLAP = 64;
    char buf[8192];
    std::string prevTail;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        std::string chunk = prevTail + std::string(buf, static_cast<size_t>(n));
        // Lower-case copy for case-insensitive search.
        std::string lower = chunk;
        for (char &c : lower) c = (char)tolower((unsigned char)c);

        for (int i = 0; MARKERS[i] != nullptr; ++i) {
            std::string marker = MARKERS[i];
            for (char &c : marker) c = (char)tolower((unsigned char)c);
            if (lower.find(marker) != std::string::npos) {
                std::string entry = std::string("odex_marker:") + MARKERS[i];
                bool dup = false;
                for (const auto &f : findings) { if (f == entry) { dup = true; break; } }
                if (!dup) findings.push_back(entry);
            }
        }
        // Retain last OVERLAP bytes for next iteration.
        if (chunk.size() > OVERLAP)
            prevTail = chunk.substr(chunk.size() - OVERLAP);
        else
            prevTail = chunk;
    }
    close(fd);

    if (!findings.empty())
        findings.push_back("odex_path:" + odexPath.substr(0, 120));

    return findings;
}

// ---------------------------------------------------------------------------
// N8 — Inline-hook / trampoline detection
// Reads the first 16 bytes of several well-known libc/libdl functions and
// checks for classic hook-trampoline byte patterns inserted by Frida, Dobby,
// ShadowHook, Pine, or similar frameworks.
//
// ARM64 pattern  : LDR Xn, [PC+imm]; BR Xn  (byte[3]==0x58, byte[7]==0xD6)
// x86-64 pattern : JMP [RIP+imm] (0xFF 0x25) or JMP rel32 (0xE9 at byte 0)
// ARM32 pattern  : Thumb-2 LDR.W PC, [PC, #imm] (0xDF 0xF8 at bytes 0-1)
// ---------------------------------------------------------------------------
static std::vector<std::string> probeInlineHooks() {
    static const char *FUNCS[] = {
        "open", "read", "write", "mmap", "munmap",
        "dlopen", "dlsym",
        nullptr
    };

    std::vector<std::string> findings;
    for (int i = 0; FUNCS[i] != nullptr; ++i) {
        void *addr = dlsym(RTLD_DEFAULT, FUNCS[i]);
        if (addr == nullptr) continue;

        // Copy the first 16 bytes of the function into a local buffer.
        // The address returned by dlsym is guaranteed to be in a mapped
        // r-xp region, so the read is always safe.
        uint8_t bytes[16] = {};
        memcpy(bytes, addr, 16);

#if defined(__aarch64__)
        // ARM64: LDR Xn, [PC+imm]; BR Xn — 8-byte trampoline
        // byte[3] == 0x58 identifies any 64-bit LDR-literal instruction.
        // byte[6] == 0x1F && byte[7] == 0xD6 identifies a BR Xn instruction.
        if (bytes[3] == 0x58 && bytes[6] == 0x1F && bytes[7] == 0xD6) {
            findings.push_back(std::string("inline_hook:arm64_ldr_br:") + FUNCS[i]);
        }
#elif defined(__arm__)
        // Thumb-2 LDR.W PC, [PC, #imm]: bytes 0-1 = 0xDF 0xF8
        if (bytes[0] == 0xDF && bytes[1] == 0xF8) {
            findings.push_back(std::string("inline_hook:arm32_ldr_pc:") + FUNCS[i]);
        }
#elif defined(__x86_64__)
        // JMP QWORD PTR [RIP+imm32] (Frida/Substrate absolute trampoline)
        if (bytes[0] == 0xFF && bytes[1] == 0x25) {
            findings.push_back(std::string("inline_hook:x86_64_jmp_rip:") + FUNCS[i]);
        }
        // JMP rel32 — may be a short-range hook redirect
        if (bytes[0] == 0xE9) {
            findings.push_back(std::string("inline_hook:x86_64_jmp_rel:") + FUNCS[i]);
        }
#elif defined(__i386__)
        if (bytes[0] == 0xFF && bytes[1] == 0x25) {
            findings.push_back(std::string("inline_hook:x86_jmp_mem:") + FUNCS[i]);
        }
        if (bytes[0] == 0xE9) {
            findings.push_back(std::string("inline_hook:x86_jmp_rel:") + FUNCS[i]);
        }
#endif
    }
    return findings;
}

// ---------------------------------------------------------------------------
// N9 — Hide My Applist (HMA) native detection
// Uses stat(2) on known HMA data paths and opendir(3)/readdir(3) to scan
// /data/misc/ for hide_my_applist* directories (v3+ uses a random suffix).
// Also checks /proc/self/maps for any HMA-related library mappings.
// ---------------------------------------------------------------------------
static std::vector<std::string> probeHMAPaths() {
    static const char *PATHS[] = {
        "/data/misc/hide_my_applist",
        "/data/system/hide_my_applist",
        "/data/user_de/0/com.tsng.hidemyapplist",
        "/data/user_de/0/cn.hidemyapplist",
        nullptr
    };

    std::vector<std::string> findings;
    struct stat st{};

    for (int i = 0; PATHS[i] != nullptr; ++i) {
        if (stat(PATHS[i], &st) == 0)
            findings.push_back(std::string("hma_stat:") + PATHS[i]);
    }

    // Scan /data/misc/ for entries whose names contain "hidemyapplist" or
    // "hide_my_applist" (HMA v3+ stores state in a randomly-suffixed directory).
    DIR *dir = opendir("/data/misc");
    if (dir != nullptr) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string name = entry->d_name;
            std::string lower = name;
            for (char &c : lower) c = (char)tolower((unsigned char)c);
            if (lower.find("hidemyapplist") != std::string::npos ||
                lower.find("hide_my_applist") != std::string::npos) {
                std::string path = std::string("/data/misc/") + name;
                bool dup = false;
                for (const auto &f : findings) { if (f == path) { dup = true; break; } }
                if (!dup) findings.push_back(std::string("hma_misc:") + path);
            }
        }
        closedir(dir);
    }

    // Check /proc/self/maps for any HMA-related library mappings.
    {
        int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            char buf[4096];
            std::string partial;
            ssize_t n;
            while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
                buf[n] = '\0';
                partial += buf;
                size_t pos;
                while ((pos = partial.find('\n')) != std::string::npos) {
                    std::string line = partial.substr(0, pos);
                    partial = partial.substr(pos + 1);
                    std::string lower = line;
                    for (char &c : lower) c = (char)tolower((unsigned char)c);
                    if (lower.find("hidemyapplist") != std::string::npos ||
                        lower.find("hide_my_applist") != std::string::npos) {
                        size_t sp = line.rfind(' ');
                        std::string path = (sp != std::string::npos)
                                               ? line.substr(sp + 1)
                                               : line;
                        std::string entry = std::string("hma_maps:") + path.substr(0, 120);
                        bool dup = false;
                        for (const auto &f : findings) {
                            if (f == entry) { dup = true; break; }
                        }
                        if (!dup) findings.push_back(entry);
                    }
                }
            }
            close(fd);
        }
    }

    return findings;
}

// ---------------------------------------------------------------------------
// N10 — ELF symbol scan (Hunter-inspired)
//
// Uses the ElfImg class (adapted from HunterRuntime) to parse the .dynsym and
// .symtab sections of every native library mapped into this process and search
// for symbols belonging to known hook frameworks.
//
// Standard dlsym() only resolves exported symbols and is subject to GOT-level
// interception; ElfImg reads the ELF sections directly from disk via mmap(2),
// bypassing both restrictions.
//
// Targets: LSPlant, Frida (gum), Dobby, ShadowHook, Pine.
// ---------------------------------------------------------------------------
static std::vector<std::string> probeElfSymbols() {
    // Known symbols exported (or left in .symtab) by hook frameworks.
    static const char *HOOK_SYMS[] = {
        // LSPlant (LSPosed's ART hook engine)
        "lsplant::InitHooks",
        "_ZN7lsplant9InitHooksEP7_JNIEnvRKNS_10InitInfoE",
        "_ZN7lsplant4HookEP7_JNIEnvP10_jmethodIDS3_",
        // Frida GumJS / Interceptor
        "frida_agent_main",
        "gum_interceptor_attach",
        "gum_interceptor_replace",
        "gum_module_find_export_by_name",
        "gum_process_find_module_by_name",
        // Dobby inline hook
        "DobbyHook",
        "DobbyDestroy",
        "DobbyInstrumentRegisterVMT",
        // ShadowHook
        "shadowhook_hook_func_addr",
        "shadowhook_unhook",
        // Pine (Android ART hook)
        "Pine_hook",
        "PineHook",
        nullptr
    };

    std::vector<std::string> findings;

    // Collect unique SO paths from /proc/self/maps.
    std::vector<std::string> soPaths;
    {
        int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return findings;
        char buf[4096];
        std::string partial;
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            partial += buf;
            size_t pos;
            while ((pos = partial.find('\n')) != std::string::npos) {
                std::string line = partial.substr(0, pos);
                partial = partial.substr(pos + 1);
                // Only consider executable or read-only pages with a path.
                if (line.find("r-xp") == std::string::npos &&
                    line.find("r--p") == std::string::npos) continue;
                size_t sp = line.rfind(' ');
                if (sp == std::string::npos) continue;
                std::string path = line.substr(sp + 1);
                if (path.size() < 4) continue;
                // Only actual .so files on disk.
                if (path.find(".so") == std::string::npos) continue;
                // Deduplicate.
                bool dup = false;
                for (const auto &p : soPaths) { if (p == path) { dup = true; break; } }
                if (!dup) soPaths.push_back(path);
            }
        }
        close(fd);
    }

    // For each SO, use ElfImg to scan for known hook symbols.
    for (const auto &soPath : soPaths) {
        anycheck::elf::ElfImg img(soPath.c_str());
        if (!img.valid()) continue;

        for (int i = 0; HOOK_SYMS[i] != nullptr; ++i) {
            AC_Elf_Addr addr = img.getSymAddress(HOOK_SYMS[i]);
            if (addr != 0) {
                // Extract the SO filename for the report.
                size_t slash = soPath.rfind('/');
                std::string soName = (slash != std::string::npos)
                                         ? soPath.substr(slash + 1)
                                         : soPath;
                std::string entry = "elf_sym:" + soName + "!" + std::string(HOOK_SYMS[i]);
                bool dup = false;
                for (const auto &f : findings) { if (f == entry) { dup = true; break; } }
                if (!dup) findings.push_back(entry);
            }
        }
    }
    return findings;
}

// ---------------------------------------------------------------------------
// JNI entry point
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectLSPosedJni(JNIEnv *env, jobject /* thiz */) {
    std::vector<std::string> allFindings;

    // N1: maps scan
    auto maps = scanMaps();
    allFindings.insert(allFindings.end(), maps.begin(), maps.end());

    // N2: dlopen probe
    auto dlo = probeDlopen();
    allFindings.insert(allFindings.end(), dlo.begin(), dlo.end());

    // N3: dlsym probe
    auto sym = probeDlsym();
    allFindings.insert(allFindings.end(), sym.begin(), sym.end());

    // N4: stat paths
    auto paths = probePaths();
    allFindings.insert(allFindings.end(), paths.begin(), paths.end());

    // N5: native bridge property
    auto bridge = probeNativeBridge();
    if (!bridge.empty()) allFindings.push_back(bridge);

    // N6: smaps Private_Dirty
    auto smaps = probeSmaps();
    allFindings.insert(allFindings.end(), smaps.begin(), smaps.end());

    // Build semicolon-separated result string
    std::string result;
    for (size_t i = 0; i < allFindings.size(); ++i) {
        if (i > 0) result += "; ";
        result += allFindings[i];
    }

    return env->NewStringUTF(result.c_str());
}

// ---------------------------------------------------------------------------
// JNI entry point — N7: own ODEX scan
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectOdexHooksJni(JNIEnv *env, jobject /* thiz */) {
    auto findings = scanOwnOdex();
    std::string result;
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i > 0) result += "; ";
        result += findings[i];
    }
    return env->NewStringUTF(result.c_str());
}

// ---------------------------------------------------------------------------
// JNI entry point — N8: inline hook trampoline detection
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectInlineHooksJni(JNIEnv *env, jobject /* thiz */) {
    auto findings = probeInlineHooks();
    std::string result;
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i > 0) result += "; ";
        result += findings[i];
    }
    return env->NewStringUTF(result.c_str());
}

// ---------------------------------------------------------------------------
// JNI entry point — N9: Hide My Applist native detection
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectHMANativeJni(JNIEnv *env, jobject /* thiz */) {
    auto findings = probeHMAPaths();
    std::string result;
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i > 0) result += "; ";
        result += findings[i];
    }
    return env->NewStringUTF(result.c_str());
}

// ---------------------------------------------------------------------------
// JNI entry point — N10: ELF symbol scan (Hunter-inspired)
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectElfSymbolsJni(JNIEnv *env, jobject /* thiz */) {
    auto findings = probeElfSymbols();
    std::string result;
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i > 0) result += "; ";
        result += findings[i];
    }
    return env->NewStringUTF(result.c_str());
}

// ---------------------------------------------------------------------------
// N11 — Audit log process detection
//
// Reads kernel audit log entries (AVC SELinux denials) from /dev/kmsg in
// non-blocking mode, or falls back to a popen("logcat -b kernel") pipe.
// Lines that contain "type=AVC" or "avc:" with suspicious SELinux contexts
// (u:r:magisk:s0, u:r:su:s0, u:r:zygisk:s0, etc.) are returned as findings.
//
// This bypasses Java logging APIs which can be hooked by LSPosed.
// ---------------------------------------------------------------------------
static std::vector<std::string> probeAuditLog() {
    std::vector<std::string> findings;

    // Root-related SELinux context keywords that should not normally appear
    // in a clean Android AVC audit log.
    static const char *ROOT_CONTEXTS[] = {
        "u:r:magisk:", "u:r:su:", "u:r:zygisk:", "u:r:zygisk_child:",
        "u:r:untrusted_app:", // legitimate but flag if in AVC with magisk/su tcontext
        nullptr
    };
    // Suspicious comm= values seen in AVC entries on rooted devices
    static const char *ROOT_COMMS[] = {
        "comm=\"magiskd\"", "comm=\"magisk64\"", "comm=\"magisk32\"",
        "comm=\"kswapd0\"",  // KSU disguise
        "comm=\"lspd\"",     "comm=\"lsposed\"",
        "comm=\"zygisk\"",   "comm=\"kpatchd\"",  // APatch
        nullptr
    };

    auto parseLine = [&](const std::string &line) {
        // Must contain "avc:" or "type=AVC" to be an audit entry
        bool isAvc = (line.find("avc:") != std::string::npos) ||
                     (line.find("type=AVC") != std::string::npos);
        if (!isAvc) return;

        // Check for suspicious SELinux contexts
        for (int i = 0; ROOT_CONTEXTS[i] != nullptr; ++i) {
            if (line.find(ROOT_CONTEXTS[i]) != std::string::npos) {
                // Extract scontext or tcontext substring for the finding
                std::string entry = "avc_ctx:" + std::string(ROOT_CONTEXTS[i]);
                bool dup = false;
                for (const auto &f : findings) { if (f == entry) { dup = true; break; } }
                if (!dup) findings.push_back(entry);
                break;
            }
        }
        // Check for suspicious process names in AVC entries
        for (int i = 0; ROOT_COMMS[i] != nullptr; ++i) {
            if (line.find(ROOT_COMMS[i]) != std::string::npos) {
                std::string entry = "avc_comm:" + std::string(ROOT_COMMS[i]);
                bool dup = false;
                for (const auto &f : findings) { if (f == entry) { dup = true; break; } }
                if (!dup) findings.push_back(entry);
                break;
            }
        }
    };

    // Strategy 1: Try to read /dev/kmsg (non-blocking; may be denied by SELinux)
    {
        int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd >= 0) {
            char buf[2048];
            ssize_t n;
            int reads = 0;
            while ((n = read(fd, buf, sizeof(buf) - 1)) > 0 && reads < 500) {
                buf[n] = '\0';
                parseLine(std::string(buf, (size_t)n));
                reads++;
            }
            close(fd);
        }
    }

    // Strategy 2: logcat -b kernel (fallback; works on many devices without READ_LOGS)
    if (findings.empty()) {
        FILE *fp = popen("logcat -b kernel -d -t 300 2>/dev/null", "r");
        if (fp) {
            char line[1024];
            int count = 0;
            while (fgets(line, sizeof(line), fp) && count < 500) {
                parseLine(std::string(line));
                count++;
            }
            pclose(fp);
        }
    }

    return findings;
}

// ---------------------------------------------------------------------------
// N12 — Native dex2oat anomaly probe
//
// Uses stat(2) to check for LSPosed dex2oat wrapper binaries.  Bypasses
// Java-layer File.exists() hooks (e.g. via LSPosed hooking File or
// libjavacrypto).  Also checks dalvik.vm.dex2oat-filter via
// __system_property_get which is not interceptable at the Java level.
// ---------------------------------------------------------------------------
static std::vector<std::string> probeDex2oatNative() {
    static const char *DEX2OAT_PATHS[] = {
        "/data/adb/lspd/dex2oat",
        "/data/adb/lspd/bin/dex2oat",
        "/data/misc/lspd/dex2oat",
        "/data/adb/modules/zygisk_lsposed/dex2oat",
        "/data/adb/lspd/framework/lspd.dex",
        "/data/adb/lspd/framework/lsp-framework.dex",
        nullptr
    };

    std::vector<std::string> findings;
    struct stat st;

    // Check dex2oat wrapper paths via raw stat()
    for (int i = 0; DEX2OAT_PATHS[i] != nullptr; ++i) {
        if (stat(DEX2OAT_PATHS[i], &st) == 0) {
            findings.push_back(std::string("dex2oat_path:") + DEX2OAT_PATHS[i]);
        }
    }

    // Check dalvik.vm.dex2oat-filter via native property getter (bypasses Java hooks)
    char propVal[PROP_VALUE_MAX] = {};
    if (__system_property_get("dalvik.vm.dex2oat-filter", propVal) > 0) {
        static const char *KNOWN[] = {
            "speed-profile", "speed", "quicken", "space-profile", "space",
            "everything", "verify", "interpret-only", "time", nullptr
        };
        bool known = false;
        for (int i = 0; KNOWN[i] != nullptr; ++i) {
            if (strcmp(propVal, KNOWN[i]) == 0) { known = true; break; }
        }
        if (!known) {
            findings.push_back(std::string("dex2oat_filter:") + propVal);
        }
    }

    return findings;
}

// ---------------------------------------------------------------------------
// N13 — Native Netlink /proc/net/netlink anomaly probe
//
// Reads /proc/net/netlink directly using open(2)/read(2) (not Java file I/O)
// to detect non-standard Netlink protocol families used by KernelSU and
// other kernel-level root frameworks for userspace ↔ kernel communication.
// ---------------------------------------------------------------------------
static std::vector<std::string> probeNetlinkNative() {
    // Standard Android Netlink protocol numbers (0–22)
    static const int STD_MAX = 22;

    std::vector<std::string> findings;
    int fd = open("/proc/net/netlink", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return findings;

    char buf[8192];
    std::string content;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        content += buf;
    }
    close(fd);

    // Parse lines: skip header, col[1] = protocol number
    bool header = true;
    size_t start = 0;
    std::map<int,int> protoCounts;
    while (true) {
        size_t end = content.find('\n', start);
        if (end == std::string::npos) break;
        std::string line = content.substr(start, end - start);
        start = end + 1;
        if (header) { header = false; continue; }
        // Tokenize
        std::vector<std::string> parts;
        std::string tok;
        for (char c : line) {
            if (c == ' ' || c == '\t') {
                if (!tok.empty()) { parts.push_back(tok); tok.clear(); }
            } else {
                tok += c;
            }
        }
        if (!tok.empty()) parts.push_back(tok);
        if (parts.size() < 3) continue;
        int proto = (int)strtol(parts[1].c_str(), nullptr, 10);
        protoCounts[proto]++;
    }

    for (auto &kv : protoCounts) {
        if (kv.first > STD_MAX) {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "netlink_proto:%d(x%d)", kv.first, kv.second);
            findings.push_back(tmp);
        }
        if (kv.second > 20 && kv.first <= STD_MAX) {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "netlink_high_count:proto=%d,n=%d", kv.first, kv.second);
            findings.push_back(tmp);
        }
    }
    return findings;
}

// ---------------------------------------------------------------------------
// JNI entry point — N11: Audit log process detection
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectAuditLogJni(JNIEnv *env, jobject /* thiz */) {
    auto findings = probeAuditLog();
    std::string result;
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i > 0) result += "; ";
        result += findings[i];
    }
    return env->NewStringUTF(result.c_str());
}

// ---------------------------------------------------------------------------
// JNI entry point — N12: Native dex2oat anomaly
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectDex2oatNativeJni(JNIEnv *env, jobject /* thiz */) {
    auto findings = probeDex2oatNative();
    std::string result;
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i > 0) result += "; ";
        result += findings[i];
    }
    return env->NewStringUTF(result.c_str());
}

// ---------------------------------------------------------------------------
// JNI entry point — N13: Native Netlink anomaly
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectNetlinkNativeJni(JNIEnv *env, jobject /* thiz */) {
    auto findings = probeNetlinkNative();
    std::string result;
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i > 0) result += "; ";
        result += findings[i];
    }
    return env->NewStringUTF(result.c_str());
}

// ---------------------------------------------------------------------------
// N14 — HMA whitelist detection via raw fstatat syscall
// Probes /data/user/0/{root_manager} for known root manager packages.
// EACCES (errno=13) means the directory exists → root manager is present.
// If all root managers return ENOENT, probes mandatory system-app directories
// (com.android.shell, com.android.settings, android) which must always exist.
// If those also return ENOENT, HMA whitelist mode is hiding packages from us.
// ---------------------------------------------------------------------------
static std::string probeHMAWhitelist() {
    static const char *ROOT_MANAGERS[] = {
        "com.topjohnwu.magisk",
        "io.github.lsposed.manager",
        "org.lsposed.manager",
        "me.weishu.kernelsu",
        "me.bmax.apatch",
        "io.github.vvb2060.magisk",
        "com.canyie.dreamland.manager",
        "com.fox2code.mmm",
        "com.github.capntrips.kernelflasher",
        nullptr
    };
    static const char *SYSTEM_APPS[] = {
        "com.android.shell",
        "com.android.settings",
        "android",
        nullptr
    };

    struct stat st{};
    std::string rootManagersFound;
    bool anyRootManagerVisible = false;

    for (int i = 0; ROOT_MANAGERS[i] != nullptr; ++i) {
        std::string path = std::string("/data/user/0/") + ROOT_MANAGERS[i];
        errno = 0;
        long res = syscall(__NR_fstatat, AT_FDCWD, path.c_str(), &st, 0);
        if (res == 0 || errno == EACCES) {
            if (!rootManagersFound.empty()) rootManagersFound += ',';
            rootManagersFound += ROOT_MANAGERS[i];
            anyRootManagerVisible = true;
        }
    }

    if (anyRootManagerVisible) {
        return std::string("root_managers:") + rootManagersFound;
    }

    // All root manager dirs returned ENOENT — check mandatory system-app dirs.
    // These must always exist on any real Android device. If they also return
    // ENOENT via the raw syscall, HMA (or a similar hook) is masking them.
    bool systemAppVisible = false;
    for (int i = 0; SYSTEM_APPS[i] != nullptr; ++i) {
        std::string path = std::string("/data/user/0/") + SYSTEM_APPS[i];
        errno = 0;
        long res = syscall(__NR_fstatat, AT_FDCWD, path.c_str(), &st, 0);
        if (res == 0 || errno == EACCES) {
            systemAppVisible = true;
            break;
        }
    }

    if (!systemAppVisible) {
        return "hma_whitelist_detected";
    }

    return "";
}

// ---------------------------------------------------------------------------
// N15 — HMA blacklist detection via raw fstatat syscall
// Reads st_nlink of /data/user/0 to obtain the kernel's physical subdirectory
// count (st_nlink - 2). On a normal Android device there are typically well
// over 100 package data directories. If HMA blacklist mode is configured to
// hide packages from our app, it may manipulate stat so that the apparent
// link count drops below 100 — a reliable anomaly indicator.
// ---------------------------------------------------------------------------
static std::string probeHMABlacklist() {
    struct stat st{};
    errno = 0;
    long res = syscall(__NR_fstatat, AT_FDCWD, "/data/user/0", &st, 0);
    if (res != 0) return "";

    int physical_count = static_cast<int>(st.st_nlink) - 2;
    if (physical_count < 0) physical_count = 0;

    if (physical_count < 100) {
        char buf[64];
        snprintf(buf, sizeof(buf), "hma_blacklist_detected:count=%d", physical_count);
        return std::string(buf);
    }
    return "";
}

// ---------------------------------------------------------------------------
// N16 — Magisk MAC anomaly via raw RTNETLINK socket
//
// Reverse-engineered from Luna libluna.so "magiskmac" method.
// Luna opens a raw AF_NETLINK / NETLINK_ROUTE socket and sends an
// RTM_GETLINK|NLM_F_DUMP request to obtain all network interfaces from the
// kernel — bypassing the Java NetworkInterface API which silently omits
// virtual interfaces (e.g. dummy0) created by Magisk's DenyList network
// namespace isolation on Android 11+.
//
// Uses AF_PACKET as ifi_family (not AF_UNSPEC) to bypass Magisk RTNETLINK
// hooks that filter AF_UNSPEC results. send() without an explicit kernel
// sockaddr_nl further avoids the sendto() hook pattern Magisk intercepts.
// With the hook bypassed, the existing rules now see Magisk's virtual
// interfaces that were previously hidden.
//
// Two rules are applied:
//   Rule A (all API levels): any interface with an all-zero MAC
//         (00:00:00:00:00:00) is a Magisk vnet artifact.
//   Rule B (Android 11+ / API_LEVEL >= 30): any dummy* interface with a
//         non-zero MAC is suspicious.  Stock devices do not have a dummy0
//         interface; its presence indicates Magisk DenyList namespace.
//
// Returns semicolon-separated findings, or empty string if none.
// ---------------------------------------------------------------------------

static int getAndroidApiLevel() {
    char buf[16] = {};
    if (__system_property_get("ro.build.version.sdk", buf) > 0) {
        return atoi(buf);
    }
    return 0;
}

static std::string probeMagiskMac() {
    std::string findings;
    const int apiLevel = getAndroidApiLevel();

    // Open raw netlink / route socket
    int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock < 0) return "";

    // Build RTM_GETLINK dump request.
    // Use AF_PACKET (not AF_UNSPEC) as ifi_family: Magisk RTNETLINK hooks
    // typically only intercept AF_UNSPEC dumps.  AF_PACKET reaches the
    // kernel unfiltered and exposes virtual interfaces Magisk creates.
    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifm;
    } req{};
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type  = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq   = 1;
    req.nlh.nlmsg_pid   = static_cast<uint32_t>(getpid());
    req.ifm.ifi_family  = AF_PACKET;

    // Use send() without an explicit kernel sockaddr_nl — the kernel accepts
    // this on an unbound netlink socket and auto-assigns the port.  This
    // avoids the sendto()-with-kernel-addr hook pattern Magisk uses.
    if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
        close(sock);
        return "";
    }

    // Receive and parse responses
    char buf[16384];
    bool done = false;
    while (!done) {
        ssize_t len = recv(sock, buf, sizeof(buf), 0);
        if (len <= 0) break;

        for (struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
             NLMSG_OK(nlh, static_cast<uint32_t>(len));
             nlh = NLMSG_NEXT(nlh, len)) {

            if (nlh->nlmsg_type == NLMSG_DONE) { done = true; break; }
            if (nlh->nlmsg_type == NLMSG_ERROR) { done = true; break; }
            if (nlh->nlmsg_type != RTM_NEWLINK)  continue;

            struct ifinfomsg *ifi = static_cast<struct ifinfomsg *>(NLMSG_DATA(nlh));
            int rta_len = static_cast<int>(nlh->nlmsg_len) - NLMSG_LENGTH(sizeof(*ifi));

            char ifName[IFNAMSIZ] = {};
            uint8_t macBytes[6] = {};
            bool hasMac = false;

            for (struct rtattr *rta = IFLA_RTA(ifi);
                 RTA_OK(rta, rta_len);
                 rta = RTA_NEXT(rta, rta_len)) {
                if (rta->rta_type == IFLA_IFNAME) {
                    size_t copyLen = RTA_PAYLOAD(rta);
                    if (copyLen >= IFNAMSIZ) copyLen = IFNAMSIZ - 1;
                    memcpy(ifName, RTA_DATA(rta), copyLen);
                    ifName[copyLen] = '\0';
                } else if (rta->rta_type == IFLA_ADDRESS) {
                    if (RTA_PAYLOAD(rta) == 6) {
                        memcpy(macBytes, RTA_DATA(rta), 6);
                        hasMac = true;
                    }
                }
            }

            // Skip loopback and unnamed interfaces
            if (ifName[0] == '\0') continue;
            if (strcmp(ifName, "lo") == 0) continue;

            // Format MAC string
            char macStr[18] = "00:00:00:00:00:00";
            if (hasMac) {
                snprintf(macStr, sizeof(macStr),
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         macBytes[0], macBytes[1], macBytes[2],
                         macBytes[3], macBytes[4], macBytes[5]);
            }

            bool isZeroMac = true;
            if (hasMac) {
                for (int b = 0; b < 6; ++b) {
                    if (macBytes[b] != 0) { isZeroMac = false; break; }
                }
            }

            // Rule A: zero MAC on any interface
            if (isZeroMac) {
                if (!findings.empty()) findings += ';';
                findings += std::string(ifName) + ":zero MAC(00:00:00:00:00:00) [Rule A]";
                continue;
            }

            // Rule B: on Android 11+, any dummy* interface with non-zero MAC
            if (apiLevel >= 30 && strncmp(ifName, "dummy", 5) == 0) {
                if (!findings.empty()) findings += ';';
                findings += std::string(ifName) + ":dummy interface on Android 11+(mac="
                    + macStr + ") [Rule B,API=" + std::to_string(apiLevel) + "]";
                continue;
            }

            // Legacy: dummy/vnet with placeholder MAC on older Android
            if (apiLevel < 30 &&
                (strncmp(ifName, "dummy", 5) == 0 || strncmp(ifName, "vnet", 4) == 0)) {
                if (strcmp(macStr, "02:00:00:00:00:00") == 0) {
                    if (!findings.empty()) findings += ';';
                    findings += std::string(ifName) + ":virt iface placeholder MAC("
                        + macStr + ") [legacy,API=" + std::to_string(apiLevel) + "]";
                }
            }
        }
    }

    close(sock);
    return findings;
}

// ---------------------------------------------------------------------------
// JNI entry point — N14: HMA whitelist detection
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectHMAWhitelistJni(JNIEnv *env, jobject /* thiz */) {
    return env->NewStringUTF(probeHMAWhitelist().c_str());
}

// ---------------------------------------------------------------------------
// JNI entry point — N15: HMA blacklist detection
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectHMABlacklistJni(JNIEnv *env, jobject /* thiz */) {
    return env->NewStringUTF(probeHMABlacklist().c_str());
}

// ---------------------------------------------------------------------------
// JNI entry point — N16: Magisk MAC anomaly detection
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectMagiskMacJni(JNIEnv *env, jobject /* thiz */) {
    return env->NewStringUTF(probeMagiskMac().c_str());
}

// ---------------------------------------------------------------------------
// N17 — KernelSU timing detection (ported from repository root a.c)
//
// Uses two side-channel probes with raw fstatat(2) timing:
//   1) short-path duel: /system/bin/su vs /system/bin/no
//   2) long-path duel : long "...su" vs long "...aa"
//
// Final risk score (same logic as a.c):
//   short_ratio > 0.98 => +40
//   long_ratio  < 1.05 => +50
//   score >= 80 => detected
// ---------------------------------------------------------------------------

static inline uint64_t read_tick() {
#if defined(__aarch64__)
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val) :: "memory");
    return val;
#else
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static inline uint64_t raw_fstatat_latency(const char *path) {
    struct stat st{};
    uint64_t start = read_tick();
#if defined(__NR_fstatat)
    (void)syscall(__NR_fstatat, AT_FDCWD, path, &st, 0);
#else
    (void)fstatat(AT_FDCWD, path, &st, 0);
#endif
    uint64_t end = read_tick();
    return end - start;
}

static double run_ksu_sidechannel_test(const char *p1, const char *p2, int samples) {
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    for (int i = 0; i < samples; ++i) {
        if ((i & 1) == 0) {
            t1 += raw_fstatat_latency(p1);
            t2 += raw_fstatat_latency(p2);
        } else {
            t2 += raw_fstatat_latency(p2);
            t1 += raw_fstatat_latency(p1);
        }
    }
    if (t2 == 0) return 0.0;
    return (double)t1 / (double)t2;
}

static std::string probeKsuTiming() {
    // a.c reference uses 200000 samples; production uses 2000 to avoid
    // post-check CPU spikes while preserving the same scoring thresholds.
    static const int SAMPLE = 2000;
    static const int PATH_MAX_LEN = 4000;

    double shortRatio = run_ksu_sidechannel_test("/system/bin/su", "/system/bin/no", SAMPLE);
    if (shortRatio <= 0.0) return "";

    std::string pClean(PATH_MAX_LEN, 'a');
    std::string pHeavy(PATH_MAX_LEN, 'a');
    pHeavy[PATH_MAX_LEN - 2] = 's';
    pHeavy[PATH_MAX_LEN - 1] = 'u';

    double longRatio = run_ksu_sidechannel_test(pHeavy.c_str(), pClean.c_str(), SAMPLE);
    if (longRatio <= 0.0) return "";

    int riskScore = 0;
    if (shortRatio > 0.98) riskScore += 40;
    if (longRatio < 1.05) riskScore += 50;

    if (riskScore >= 80) {
        char shortStr[32], longStr[32], scoreStr[16];
        snprintf(shortStr, sizeof(shortStr), "%.4f", shortRatio);
        snprintf(longStr, sizeof(longStr), "%.4f", longRatio);
        snprintf(scoreStr, sizeof(scoreStr), "%d", riskScore);
        return std::string("ksu_timing_detected:short_ratio=") + shortStr +
               ";long_ratio=" + longStr + ";score=" + scoreStr;
    }
    return "";
}

// ---------------------------------------------------------------------------
// JNI entry point — N17: KernelSU timing detection
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectKsuTimingJni(JNIEnv *env, jobject /* thiz */) {
    return env->NewStringUTF(probeKsuTiming().c_str());
}

// ---------------------------------------------------------------------------
// N18 — KernelSU LKM mode detection
//
// Checks for artifacts that are unique to KernelSU running as a Loadable
// Kernel Module (LKM / GKI mode) rather than being compiled into the kernel:
//
//   1. /sys/module/kernelsu  — sysfs module directory; present for every
//      loaded Linux kernel module; much harder to hide than /proc/modules.
//   2. /sys/module/ksu       — alternate module name used by some forks.
//   3. /dev/ksu              — character device registered by KSU misc driver
//      for userspace ↔ kernel IPC; unique to LKM mode.
//   4. /proc/mounts overlayfs scan — KSU LKM applies system overlays via
//      overlayfs (upperdir=/data/adb/...) rather than loop devices; the Java
//      File API can be hooked by LSPosed; this uses raw open/read syscalls.
//
// Uses raw stat(2) (via fstatat syscall) and open/read to avoid any Java
// or libc hooks.
//
// Returns a semicolon-separated findings string, or "" when clean.
// ---------------------------------------------------------------------------

static std::string probeKsuLkm() {
    std::string findings;

    struct stat st{};

    static const char *SYSFS_PATHS[] = {
        "/sys/module/kernelsu",
        "/sys/module/ksu",
        "/dev/ksu",
        nullptr
    };

    for (int i = 0; SYSFS_PATHS[i] != nullptr; ++i) {
        errno = 0;
        long res = syscall(__NR_fstatat, AT_FDCWD, SYSFS_PATHS[i], &st, 0);
        if (res == 0 || errno == EACCES) {
            if (!findings.empty()) findings += ';';
            findings += std::string("sysfs:") + SYSFS_PATHS[i];
        }
    }

    // Scan /proc/mounts for overlayfs entries with KSU-related upperdir/workdir.
    // Use raw open/read to bypass any libc hook on fopen.
    static const char *KSU_OVERLAY_NEEDLES[] = {
        "upperdir=/data/adb",
        "workdir=/data/adb",
        "lowerdir=/data/adb",
        "/data/adb/ksu",
        "/data/adb/modules",
        nullptr
    };

    int fd = open("/proc/mounts", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char buf[8192];
        ssize_t n;
        std::string line;
        while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            for (ssize_t charIdx = 0; charIdx < n; ++charIdx) {
                char c = buf[charIdx];
                if (c == '\n') {
                    // Check if this line is an overlay mount with KSU paths
                    bool isOverlay = (line.find("overlay ") != std::string::npos ||
                                      line.find(" overlay ") != std::string::npos);
                    if (isOverlay) {
                        for (int k = 0; KSU_OVERLAY_NEEDLES[k] != nullptr; ++k) {
                            if (line.find(KSU_OVERLAY_NEEDLES[k]) != std::string::npos) {
                                if (!findings.empty()) findings += ';';
                                // Truncate long lines to avoid oversized JNI strings
                                findings += "overlayfs:" + line.substr(0, 80);
                                break;
                            }
                        }
                    }
                    line.clear();
                } else {
                    line += c;
                }
            }
        }
        close(fd);
    }

    return findings;
}

// ---------------------------------------------------------------------------
// JNI entry point — N18: KernelSU LKM mode detection
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_anycheck_app_detection_NativeDetector_detectKsuLkmJni(JNIEnv *env, jobject /* thiz */) {
    return env->NewStringUTF(probeKsuLkm().c_str());
}
