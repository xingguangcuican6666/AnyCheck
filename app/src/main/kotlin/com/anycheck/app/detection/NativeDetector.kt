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

    private external fun detectLSPosedJni(): String
    private external fun detectOdexHooksJni(): String
    private external fun detectInlineHooksJni(): String
    private external fun detectHMANativeJni(): String
}
