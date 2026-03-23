#include <jni.h>
#include <string>
#include <vector>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <android/log.h>
#include <stdint.h>

#define LOG_TAG "anycheck_native"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

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
