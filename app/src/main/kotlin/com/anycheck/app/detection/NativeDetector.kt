package com.anycheck.app.detection

/**
 * JNI wrapper for the native LSPosed detection library (libanycheck.so).
 *
 * The native probes use raw POSIX syscalls (open/read/stat) and bionic-level
 * APIs (dlopen, dlsym, __system_property_get) which are not intercepted by
 * LSPlant's Java-layer hooking engine.
 */
object NativeDetector {

    private var libraryLoaded = false

    init {
        try {
            System.loadLibrary("anycheck")
            libraryLoaded = true
        } catch (_: UnsatisfiedLinkError) {
        }
    }

    /**
     * Runs all 6 native probes and returns a semicolon-separated string of
     * findings.  Returns an empty string if nothing is detected or if the
     * native library could not be loaded.
     */
    fun detectLSPosed(): String {
        if (!libraryLoaded) return ""
        return try {
            detectLSPosedJni()
        } catch (_: Throwable) {
            ""
        }
    }

    /**
     * Scans this app's own compiled ODEX (base.odex) for LSPosed / hook-framework
     * string markers using raw open(2)/read(2) syscalls.  Even when LSPosed is
     * not explicitly targeting this app, its presence in the zygote can leave
     * trace strings in the compiled code artifact.
     */
    fun detectOdexHooks(): String {
        if (!libraryLoaded) return ""
        return try {
            detectOdexHooksJni()
        } catch (_: Throwable) {
            ""
        }
    }

    /**
     * Inspects the first bytes of well-known libc/libdl functions for common
     * inline-hook trampoline patterns (Frida, Dobby, ShadowHook, Pine).
     * Returns a semicolon-separated list of hooked function names with the
     * detected pattern type, or an empty string if no hooks are found.
     */
    fun detectInlineHooks(): String {
        if (!libraryLoaded) return ""
        return try {
            detectInlineHooksJni()
        } catch (_: Throwable) {
            ""
        }
    }

    /**
     * Checks for Hide My Applist (HMA) at the native level: stat() on known
     * HMA data paths, readdir() scan of /data/misc/ for hide_my_applist*
     * directories (v3+ random suffix), and /proc/self/maps for HMA library
     * mappings.  Returns a semicolon-separated findings string or empty string.
     */
    fun detectHMANative(): String {
        if (!libraryLoaded) return ""
        return try {
            detectHMANativeJni()
        } catch (_: Throwable) {
            ""
        }
    }

    /**
     * Scans every native library mapped into this process by directly parsing
     * the ELF .dynsym and .symtab sections via mmap(2) (Hunter-inspired ElfImg
     * approach).  This bypasses standard dlsym() and GOT-level hooks.
     * Returns a semicolon-separated list of "elf_sym:<lib>!<symbol>" findings,
     * or an empty string if no hook-framework symbols are found.
     */
    fun detectElfSymbols(): String {
        if (!libraryLoaded) return ""
        return try {
            detectElfSymbolsJni()
        } catch (_: Throwable) {
            ""
        }
    }

    /**
     * Reads kernel audit log entries (AVC SELinux denials) from /dev/kmsg in
     * non-blocking mode, or falls back to a logcat -b kernel pipe.  Parses
     * lines for suspicious SELinux contexts (u:r:magisk:s0, u:r:su:s0, …) and
     * root-related comm= values that reveal root daemon activity.
     *
     * This is the native backend for audit log process detection (Check 25).
     */
    fun detectAuditLog(): String {
        if (!libraryLoaded) return ""
        return try {
            detectAuditLogJni()
        } catch (_: Throwable) {
            ""
        }
    }

    /**
     * Uses stat(2) in native code to check for LSPosed dex2oat wrapper binaries
     * and __system_property_get for non-standard dex2oat-filter values.
     * More reliable than Java File.exists() which can be hooked by LSPosed.
     */
    fun detectDex2oatNative(): String {
        if (!libraryLoaded) return ""
        return try {
            detectDex2oatNativeJni()
        } catch (_: Throwable) {
            ""
        }
    }

    /**
     * Reads /proc/net/netlink directly via open(2)/read(2) syscalls to detect
     * non-standard Netlink protocol families used by kernel-level root frameworks
     * (KernelSU, APatch) for userspace ↔ kernel IPC.
     */
    fun detectNetlinkNative(): String {
        if (!libraryLoaded) return ""
        return try {
            detectNetlinkNativeJni()
        } catch (_: Throwable) {
            ""
        }
    }

    private external fun detectLSPosedJni(): String
    private external fun detectOdexHooksJni(): String
    private external fun detectInlineHooksJni(): String
    private external fun detectHMANativeJni(): String
    private external fun detectElfSymbolsJni(): String
    private external fun detectAuditLogJni(): String
    private external fun detectDex2oatNativeJni(): String
    private external fun detectNetlinkNativeJni(): String
}
