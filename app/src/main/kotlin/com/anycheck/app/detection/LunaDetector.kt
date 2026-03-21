package com.anycheck.app.detection

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.PackageManager
import android.view.accessibility.AccessibilityManager
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Luna-inspired detection engine.
 *
 * Implements detection methods reverse-engineered from the Luna safety checker
 * (luna.safe.luna / JNI methods in libluna.so), covering:
 *  - findlsp          → LSPosed API system property check
 *  - findksu          → KernelSU daemon service property check
 *  - checkappnum      → Magisk daemon service property check
 *  - psdir            → PATH-directory su/root binary scan
 *  - rustmagisk       → APatch process scan via /proc
 *  - fhma             → suspicious system-file size check (stat)
 *  - checksuskernel   → kernel-level stat anomaly via /proc/net/unix + SELinux context
 *  - magiskmounts     → /proc/mounts Magisk bind-mount / overlayfs detection
 *  - zygoteinject     → Zygote injection via SELinux context inspection
 *  - tmpfsmount       → tmpfs SELinux context anomaly on /mnt/obb and /mnt/asec
 *  - procscan         → /proc cmdline scan for APatch/lsposed/shamiko + root-linked overlayfs only
 *  - roots            → root binary and /data/adb file existence
 *  - kernels/tests    → /proc/version custom-kernel string + boot cmdline
 *  - findauth         → /data/local/tmp/attestation file presence
 *  - getEvilModules   → root native library files in system dirs and process maps
 *  - getapps          → installed root-manager and hook-framework package scan
 *  - findapply        → accessibility service scan for Auto.js automation tools
 *  - findbootbl       → bootloader unlock status via ro.boot.verifiedbootstate
 *  - checknum         → persist.sys.vold_app_data_isolation property check
 *  - scanlib          → PackageManager nativeLibraryDir scan for root .so files
 *  - wNxM8s/K0ajGz    → HideMyAppList / TaiChi root-hiding app presence
 *  - magiskmac        → /sys/class/net MAC address spoofing anomaly
 */
class LunaDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkLSPosedApiProperty(),
        checkKernelSUDaemon(),
        checkMagiskDaemonProperty(),
        checkSuInPathDirectories(),
        checkAPatchProcesses(),
        checkSuspiciousFileSize(),
        checkKernelStatAnomaly(),
        checkMagiskProcMounts(),
        checkZygoteInjection(),
        checkTmpfsMountAnomaly(),
        // New: methods from new.md
        checkProcScan(),
        checkRootFiles(),
        checkKernelVersion(),
        checkAttestationFile(),
        checkEvilModules(),
        checkInstalledRootApps(),
        checkAccessibilityServices(),
        checkBootloaderUnlocked(),
        checkVoldIsolationProperty(),
        checkNativeLibraryScan(),
        checkSensitivePackagesPresence(),
        checkMacAddressAnomaly()
    )

    // -------------------------------------------------------------------------
    // Luna: findlsp
    // __system_property_get(DAT_001407b0, buf)  → atoi(buf) >= 1 means LSPosed
    // -------------------------------------------------------------------------
    private fun checkLSPosedApiProperty(): DetectionResult {
        val lspProps = listOf(
            "persist.lsp.api",
            "init.svc.lspd",
            "ro.lsposed.version",
            "persist.lsp.module_list"
        )
        val found = mutableListOf<String>()
        for (prop in lspProps) {
            val value = getSystemProperty(prop)
            if (value.isNotEmpty()) {
                found.add("$prop=$value")
                // Mirror Luna's atoi(buf) >= 1 check for persist.lsp.api
                if (prop == "persist.lsp.api") {
                    val apiLevel = value.toIntOrNull() ?: 0
                    if (apiLevel >= 1) found.add("lsp_api_level=$apiLevel")
                }
            }
        }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_lsp_prop",
                name = "LSPosed API Property Detected",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "LSPosed-specific system properties found.",
                detailedReason = "Luna-method (findlsp): __system_property_get on LSPosed API property. " +
                    "Found: ${found.joinToString(", ")}. " +
                    "persist.lsp.api is set by LSPosed and contains its API version number.",
                solution = "Disable or uninstall LSPosed to remove these properties.",
                technicalDetail = "Props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "luna_lsp_prop",
                name = "LSPosed API Property",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No LSPosed-specific system properties found.",
                detailedReason = "Luna-method (findlsp): None of the known LSPosed system properties " +
                    "(persist.lsp.api, init.svc.lspd) were found.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: findksu / checkksuboot
    // __system_property_get(DAT_00140540, buf)  → 0 < length means KSU daemon running
    // -------------------------------------------------------------------------
    private fun checkKernelSUDaemon(): DetectionResult {
        val ksuServiceProps = listOf(
            "init.svc.ksuud",
            "init.svc.ksu",
            "sys.init.ksuud_ready",
            "init.svc.kernelsu"
        )
        val found = mutableListOf<String>()
        for (prop in ksuServiceProps) {
            val value = getSystemProperty(prop)
            if (value.isNotEmpty()) found.add("$prop=$value")
        }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_ksu_daemon",
                name = "KernelSU Daemon Service Property",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "KernelSU daemon service properties found.",
                detailedReason = "Luna-method (findksu): __system_property_get confirmed KernelSU daemon. " +
                    "Found: ${found.joinToString(", ")}. " +
                    "init.svc.ksuud is set by the Android init system when the KernelSU " +
                    "userspace daemon (ksuud) is active.",
                solution = "Uninstall KernelSU via the KernelSU Manager app or flash a stock kernel.",
                technicalDetail = "Service props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "luna_ksu_daemon",
                name = "KernelSU Daemon Service Property",
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No KernelSU daemon service properties found.",
                detailedReason = "Luna-method (findksu): None of the KernelSU service properties " +
                    "(init.svc.ksuud, init.svc.ksu) were found.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: checkappnum
    // __system_property_get(DAT_001405f0, buf) → exists means Magisk daemon active
    // -------------------------------------------------------------------------
    private fun checkMagiskDaemonProperty(): DetectionResult {
        val magiskServiceProps = listOf(
            "init.svc.magiskd",
            "init.svc.magisk",
            "init.svc.magisksu"
        )
        val found = mutableListOf<String>()
        for (prop in magiskServiceProps) {
            val value = getSystemProperty(prop)
            if (value.isNotEmpty()) found.add("$prop=$value")
        }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_magisk_svc_prop",
                name = "Magisk Daemon Service Property",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Magisk daemon service property found.",
                detailedReason = "Luna-method (checkappnum): __system_property_get confirmed Magisk daemon. " +
                    "Found: ${found.joinToString(", ")}. " +
                    "init.svc.magiskd is set by the Android init system when the Magisk daemon is running.",
                solution = "Uninstall Magisk via the Magisk Manager app.",
                technicalDetail = "Service props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "luna_magisk_svc_prop",
                name = "Magisk Daemon Service Property",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Magisk daemon service properties found.",
                detailedReason = "Luna-method (checkappnum): None of the known Magisk service properties were found.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: psdir
    // getenv("PATH") → scan each directory for su / busybox / magisk binaries
    // -------------------------------------------------------------------------
    private fun checkSuInPathDirectories(): DetectionResult {
        val pathEnv = System.getenv("PATH") ?: ""
        val pathDirs = pathEnv.split(":").filter { it.isNotEmpty() }
        val rootBinaries = listOf("su", "busybox", "supolicy", "magisk", "resetprop", "ksud", "apd")
        val found = mutableListOf<String>()

        for (dir in pathDirs) {
            for (binary in rootBinaries) {
                val f = File(dir, binary)
                if (f.exists()) found.add("$dir/$binary")
            }
        }

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_path_su",
                name = "Root Binaries in PATH",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Root-related binaries found in PATH directories.",
                detailedReason = "Luna-method (psdir): Scanned getenv(PATH) directories for root binaries. " +
                    "Found: ${found.joinToString(", ")}. " +
                    "Root binaries placed in PATH directories grant easy shell-level root access.",
                solution = "Remove root tools to eliminate these binaries from PATH.",
                technicalDetail = "Found in PATH: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "luna_path_su",
                name = "Root Binaries in PATH",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No root binaries found in PATH directories.",
                detailedReason = "Luna-method (psdir): No root-related binaries found when scanning " +
                    "getenv(PATH) directories.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: rustmagisk (APatch detection)
    // popen(cmd, "r") → fgets lines → count > 100 means suspicious
    // Detects APatch-specific processes via /proc scan.
    // -------------------------------------------------------------------------
    private fun checkAPatchProcesses(): DetectionResult {
        val apatchPatterns = listOf("apd", "apatch", "kpatch", "kp_su", "magiskd", "magisk32", "magisk64")
        val found = mutableListOf<String>()
        var procCount = 0

        try {
            val procDir = File("/proc")
            val pidDirs = procDir.listFiles { f ->
                f.isDirectory && f.name.all { it.isDigit() }
            } ?: emptyArray()

            for (pidDir in pidDirs) {
                val cmdlineFile = File(pidDir, "cmdline")
                if (!cmdlineFile.canRead()) continue
                val cmdline = cmdlineFile.readBytes()
                    .map { b -> if (b == 0.toByte()) ' ' else b.toInt().toChar() }
                    .joinToString("")
                    .trim()
                if (cmdline.isEmpty()) continue
                procCount++
                for (pattern in apatchPatterns) {
                    if (cmdline.contains(pattern, ignoreCase = true) &&
                        found.none { it.contains(pattern) }
                    ) {
                        found.add("$pattern (pid=${pidDir.name}): $cmdline")
                    }
                }
            }
        } catch (_: Exception) {}

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_apatch_proc",
                name = "APatch/Root Process Detected",
                category = DetectionCategory.APATCH,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "APatch or root framework processes found running.",
                detailedReason = "Luna-method (rustmagisk): /proc scan for APatch/root process names. " +
                    "Found: ${found.joinToString(", ")}. " +
                    "apd is the APatch daemon; its presence confirms APatch is active. " +
                    "magiskd indicates Magisk is running.",
                solution = "Uninstall APatch via the APatch Manager app, or Magisk via Magisk Manager.",
                technicalDetail = "Processes: ${found.joinToString("; ")}; total procs scanned: $procCount"
            )
        } else {
            DetectionResult(
                id = "luna_apatch_proc",
                name = "APatch/Root Process",
                category = DetectionCategory.APATCH,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No APatch or root framework processes detected.",
                detailedReason = "Luna-method (rustmagisk): No APatch-related process names found in /proc.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: fhma
    // stat(DAT_00140690, &buf) → buf.st_size > 0x7FF (2047) means suspicious
    // Checks that small system config files have not grown unexpectedly.
    // -------------------------------------------------------------------------
    private fun checkSuspiciousFileSize(): DetectionResult {
        // Maps path → maximum expected size in bytes.
        // Luna flags size > 2047 bytes on a particular file; we apply the same
        // threshold to small system files that root tools may replace.
        val sizeThresholds = mapOf(
            "/proc/self/attr/current" to 512L
        )
        val suspicious = mutableListOf<String>()

        for ((path, maxSize) in sizeThresholds) {
            val file = File(path)
            if (!file.exists()) continue
            try {
                val size = file.length()
                if (size > maxSize) {
                    suspicious.add("$path (size=$size B, expected ≤$maxSize B)")
                }
            } catch (_: Exception) {}
        }

        return if (suspicious.isNotEmpty()) {
            DetectionResult(
                id = "luna_file_size",
                name = "Suspicious File Size Anomaly",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "System files have unexpected sizes, indicating possible tampering.",
                detailedReason = "Luna-method (fhma): stat() check revealed files with anomalous sizes. " +
                    "${suspicious.joinToString("; ")}. " +
                    "Root tools may replace or append to system files, inflating their size beyond expected.",
                solution = "Restore affected system files from a stock firmware image.",
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_file_size",
                name = "File Size Anomaly",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "No suspicious file size anomalies detected.",
                detailedReason = "Luna-method (fhma): Checked system files for size anomalies; none found.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: checksuskernel
    // stat(DAT_00140650, &buf) → (buf.st_nlink & 0x1FF) != 365 means suspicious
    // We implement an equivalent check via /proc/net/unix socket enumeration
    // and SELinux context inspection.
    // -------------------------------------------------------------------------
    private fun checkKernelStatAnomaly(): DetectionResult {
        val suspicious = mutableListOf<String>()

        try {
            // Check /proc/self/attr/current for unexpected SELinux context
            val attrFile = File("/proc/self/attr/current")
            if (attrFile.exists() && attrFile.canRead()) {
                val ctx = attrFile.readText().trim().trimEnd('\u0000')
                // An app running with an su or root SELinux context is suspicious
                if ((ctx.contains("su", ignoreCase = true) ||
                        ctx.contains("magisk", ignoreCase = true)) &&
                    !ctx.contains("untrusted_app")
                ) {
                    suspicious.add("/proc/self/attr/current: elevated SELinux context ($ctx)")
                }
            }

            // Check /proc/net/unix for root framework UNIX sockets (proxy for st_nlink anomaly)
            val unixSockets = File("/proc/net/unix")
            if (unixSockets.canRead()) {
                val content = unixSockets.readText()
                val rootSocketMarkers = listOf("magisk", "@ksu", "lspd", "apatch", "@KSUUD")
                val hits = rootSocketMarkers.filter { content.contains(it, ignoreCase = true) }
                if (hits.isNotEmpty()) {
                    suspicious.add("/proc/net/unix: root sockets detected (${hits.joinToString(", ")})")
                }
            }
        } catch (_: Exception) {}

        return if (suspicious.isNotEmpty()) {
            DetectionResult(
                id = "luna_kernel_stat",
                name = "Kernel Stat Anomaly Detected",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Kernel-level anomalies detected via /proc inspection.",
                detailedReason = "Luna-method (checksuskernel): Kernel stat anomaly checks found: " +
                    "${suspicious.joinToString("; ")}. " +
                    "Root frameworks register UNIX sockets in /proc/net/unix and may run with " +
                    "elevated SELinux contexts.",
                solution = "These kernel-level indicators are cleared when root frameworks are fully uninstalled.",
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_kernel_stat",
                name = "Kernel Stat Anomaly",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No kernel stat anomalies detected.",
                detailedReason = "Luna-method (checksuskernel): No kernel anomalies found in /proc.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: magiskmounts
    // Parses /proc/mounts (equivalent to /proc/self/mounts) looking for entries
    // characteristic of Magisk bind-mounts, overlayfs, and mirror paths used by
    // Magisk to hide its modifications from the regular filesystem namespace.
    // -------------------------------------------------------------------------
    private fun checkMagiskProcMounts(): DetectionResult {
        val suspicious = mutableListOf<String>()

        try {
            val mounts = File("/proc/self/mounts")
            if (mounts.canRead()) {
                val lines = mounts.readLines()
                // Only flag unambiguously Magisk/KSU-specific markers.
                // Excluded intentionally:
                // • /data_mirror  — Android 11+ new namespace mechanism (normal on stock AOSP)
                // • /apex/com.android.os — APEX partition present on all modern Android devices
                // Both of the above appear on clean devices and must not be treated as root signals.
                val magiskMarkers = listOf(
                    "magisk", ".magisk",
                    "worker/upper/data",
                    "/sbin/.core", "@ksu"
                )
                for (line in lines) {
                    val lower = line.lowercase()
                    for (marker in magiskMarkers) {
                        if (lower.contains(marker.lowercase()) &&
                            suspicious.none { it.contains(marker) }
                        ) {
                            suspicious.add("$marker in mount entry: ${line.take(120)}")
                        }
                    }
                }
            }
        } catch (_: Exception) {}

        return if (suspicious.isNotEmpty()) {
            DetectionResult(
                id = "luna_magisk_mounts",
                name = "Magisk Mount Entries Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Magisk-related entries found in /proc/self/mounts.",
                detailedReason = "Luna-method (magiskmounts): /proc/self/mounts contains characteristic " +
                    "Magisk bind-mount or overlay entries. " +
                    "Found: ${suspicious.joinToString("; ")}. " +
                    "Magisk hides itself and its modules by creating bind-mounts and overlay filesystems " +
                    "that leave traces in the mount table.",
                solution = "Uninstall Magisk via the Magisk Manager app and reboot to restore stock mounts.",
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_magisk_mounts",
                name = "Magisk Mount Entries",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Magisk-related mount entries found.",
                detailedReason = "Luna-method (magiskmounts): /proc/self/mounts contains no known " +
                    "Magisk-specific bind-mount or overlay markers.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: zygoteinject
    // Checks the SELinux context of /proc/self/attr/current and related paths
    // for evidence of Zygote injection by Magisk or LSPosed.
    // Luna detects: attr_prev containing "zygote" → possible Magisk injection.
    // Native Test: verifies /proc/self/attr/current, /mnt, /mnt/obb, /mnt/asec
    // do NOT carry "zygote" / injected context without being untrusted_app.
    // -------------------------------------------------------------------------
    private fun checkZygoteInjection(): DetectionResult {
        val suspicious = mutableListOf<String>()

        try {
            val attrFile = File("/proc/self/attr/current")
            if (attrFile.canRead()) {
                val ctx = attrFile.readText().trim().trimEnd('\u0000')
                // A process injected via Zygote by Magisk may carry a context that
                // references "zygote" but is no longer labeled as untrusted_app,
                // indicating the SELinux label was altered post-fork.
                if (ctx.contains("zygote", ignoreCase = true) &&
                    !ctx.contains("untrusted_app")
                ) {
                    suspicious.add("/proc/self/attr/current: zygote-related context without untrusted_app ($ctx)")
                }
            }

            // Also check /proc/self/attr/prev when readable — Magisk injection leaves
            // the previous domain label in attr_prev containing "zygote".
            val attrPrev = File("/proc/self/attr/prev")
            if (attrPrev.canRead()) {
                val prev = attrPrev.readText().trim().trimEnd('\u0000')
                if (prev.contains("zygote", ignoreCase = true)) {
                    suspicious.add("/proc/self/attr/prev: contains 'zygote' ($prev) — possible Magisk injection")
                }
            }
        } catch (_: Exception) {}

        return if (suspicious.isNotEmpty()) {
            DetectionResult(
                id = "luna_zygote_inject",
                name = "Zygote Injection Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "SELinux context indicates possible Zygote-level injection by Magisk/LSPosed.",
                detailedReason = "Luna-method (zygoteinject): SELinux context analysis found: " +
                    "${suspicious.joinToString("; ")}. " +
                    "Magisk and LSPosed hook into Zygote to inject code into every new app process. " +
                    "This leaves characteristic SELinux context traces in /proc/self/attr/.",
                solution = "Uninstall Magisk and LSPosed, then verify SELinux policy is restored to stock.",
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_zygote_inject",
                name = "Zygote Injection",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No Zygote injection indicators found in SELinux contexts.",
                detailedReason = "Luna-method (zygoteinject): /proc/self/attr/current and attr/prev " +
                    "show no signs of Zygote-level injection.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Native Test: tmpfsmount
    // Native Test checks /mnt, /mnt/obb, /mnt/asec via fstatat() and compares
    // their SELinux xattr (getxattr "security.selinux") against expected values
    // u:object:tmpfs: / _r:tmpfs:sf / tmpfs:s0.
    // Magisk uses private tmpfs mounts on these paths to isolate its namespace;
    // the presence of a non-standard tmpfs context on them is suspicious.
    // -------------------------------------------------------------------------
    private fun checkTmpfsMountAnomaly(): DetectionResult {
        val suspicious = mutableListOf<String>()

        // Paths expected to be simple tmpfs directories with standard SELinux labels.
        // Root frameworks (especially Magisk) mount private tmpfs namespaces here.
        val checkPaths = listOf("/mnt/obb", "/mnt/asec", "/mnt")

        try {
            val mounts = File("/proc/self/mounts")
            if (mounts.canRead()) {
                val mountContent = mounts.readText()
                for (path in checkPaths) {
                    // A private tmpfs overlaid on these dirs by Magisk will appear
                    // as a second "tmpfs <path>" entry that overrides the stock one.
                    val matches = mountContent.lines().filter { line ->
                        val parts = line.split(" ")
                        parts.size >= 3 &&
                            parts[1] == path &&
                            parts[2].lowercase() == "tmpfs"
                    }
                    if (matches.size > 1) {
                        suspicious.add("$path has ${matches.size} tmpfs mounts (expected 1) — possible Magisk private namespace")
                    }
                }
            }

            // Additionally check whether these directories are accessible at all —
            // if Magisk has replaced them with an isolated tmpfs, readdir may behave
            // differently than expected on a stock device.
            for (path in listOf("/mnt/obb", "/mnt/asec")) {
                val dir = File(path)
                if (!dir.exists()) {
                    suspicious.add("$path does not exist (unexpected on a standard Android system)")
                }
            }
        } catch (_: Exception) {}

        return if (suspicious.isNotEmpty()) {
            DetectionResult(
                id = "luna_tmpfs_mount",
                name = "Tmpfs Mount Anomaly Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Suspicious tmpfs mounts detected on system mount points.",
                detailedReason = "Native-Test-method (tmpfsmount): Anomalies found on /mnt/obb or /mnt/asec: " +
                    "${suspicious.joinToString("; ")}. " +
                    "Magisk creates private tmpfs namespaces on these paths to isolate its module overlays " +
                    "from the global mount namespace, leaving multiple tmpfs entries for the same path.",
                solution = "Uninstall Magisk and reboot to restore stock mount namespaces.",
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_tmpfs_mount",
                name = "Tmpfs Mount Anomaly",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No suspicious tmpfs mount anomalies detected.",
                detailedReason = "Native-Test-method (tmpfsmount): /mnt/obb and /mnt/asec mount entries " +
                    "appear normal.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: procscan
    // Scans /proc/<pid>/cmdline for root framework processes (APatch, lsposed,
    // _magisk, shamiko, zygiskd) and /proc/self/mountinfo for *suspicious*
    // overlayfs entries.
    //
    // False-positive note: Android uses overlayfs legitimately for APEX packages
    // (/apex/com.android.*), vendor/product RRO themes, and OEM system mounts.
    // We only flag an overlay mount when it meets at least one of these criteria:
    //   1. Its superblock options (lowerdir= / upperdir=) reference known root-tool
    //      working directories (/data/adb/, /magisk/, /sbin/.core, @ksu).
    //   2. It is mounted on a system path (/system, /vendor, /product, /sbin) and
    //      is NOT an APEX or RRO path — i.e., it has a non-empty lowerdir that
    //      doesn't point exclusively to read-only system partitions.
    // Both APEX overlays and system RRO overlays are explicitly whitelisted.
    // -------------------------------------------------------------------------
    private fun checkProcScan(): DetectionResult {
        val suspiciousProcs = listOf("APatch", "lsposed", "_magisk", "shamiko", "zygiskd", "magiskd")
        val foundProcs = mutableListOf<String>()
        val foundOverlay = mutableListOf<String>()

        try {
            val procDir = File("/proc")
            val pidDirs = procDir.listFiles { f ->
                f.isDirectory && f.name.all { it.isDigit() }
            } ?: emptyArray()
            for (pidDir in pidDirs) {
                val cmdlineFile = File(pidDir, "cmdline")
                if (!cmdlineFile.canRead()) continue
                val cmdline = cmdlineFile.readBytes()
                    .map { b -> if (b == 0.toByte()) ' ' else b.toInt().toChar() }
                    .joinToString("").trim()
                if (cmdline.isEmpty()) continue
                for (pattern in suspiciousProcs) {
                    if (cmdline.contains(pattern, ignoreCase = true) &&
                        foundProcs.none { it.contains(pattern, ignoreCase = true) }
                    ) {
                        foundProcs.add("$pattern(pid=${pidDir.name})")
                    }
                }
            }
        } catch (_: Exception) {}

        try {
            val mountInfo = File("/proc/self/mountinfo")
            if (mountInfo.canRead()) {
                for (line in mountInfo.readLines()) {
                    val mp = parseSuspiciousOverlayMount(line)
                    if (mp != null && !foundOverlay.contains(mp)) foundOverlay.add(mp)
                }
            }
        } catch (_: Exception) {}

        val all = foundProcs + foundOverlay.map { "overlay@$it" }
        return if (all.isNotEmpty()) {
            DetectionResult(
                id = "luna_procscan",
                name = "Suspicious Processes / Root Overlay Mounts",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "Root framework processes or root-linked overlayfs mounts found.",
                detailedReason = "Luna-method (procscan): /proc/<pid>/cmdline and /proc/self/mountinfo " +
                    "revealed: ${all.joinToString(", ")}. " +
                    "Only overlays whose lowerdir/upperdir point to root-tool paths (e.g. /data/adb, /magisk) " +
                    "or that cover system paths outside APEX/RRO are flagged.",
                solution = "Uninstall root frameworks and reboot.",
                technicalDetail = all.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_procscan",
                name = "Process / Root Overlay Scan",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No suspicious root processes or root-linked overlay mounts found.",
                detailedReason = "Luna-method (procscan): No known root process names in /proc and no " +
                    "root-tool-linked overlayfs entries in mountinfo.",
                solution = "No action required."
            )
        }
    }

    /**
     * Parses a single /proc/self/mountinfo line and returns the mount point string
     * if — and only if — it represents a *suspicious* overlayfs mount.
     *
     * Mountinfo format (space-separated):
     *   mount_id  parent_id  major:minor  root  mount_point  mount_opts
     *   [optional tagged fields...]  -  fs_type  mount_source  super_opts
     *
     * Legitimate (whitelisted) overlay mounts on clean Android:
     *   • /apex/com.android.*          — APEX package overlays
     *   • /system/overlay              — System RRO (Runtime Resource Overlay)
     *   • /vendor/overlay              — Vendor RRO
     *   • /product/overlay             — Product RRO
     *   • /system_ext/overlay          — SystemExt RRO
     *   • /odm/overlay                 — ODM RRO
     *
     * Suspicious overlays are those where either:
     *   (a) superblock options contain root-tool working paths in lowerdir=/upperdir=
     *   (b) mount point covers a system partition AND lowerdir has a non-system source
     *       (i.e., Magisk modules redirecting /system reads through /data/adb/modules)
     */
    private fun parseSuspiciousOverlayMount(line: String): String? {
        val parts = line.split(" ")

        // Locate the "-" separator between optional fields and fs info
        val dashIdx = parts.indexOf("-")
        if (dashIdx < 0) return null

        val fsType = parts.getOrNull(dashIdx + 1) ?: return null
        if (!fsType.equals("overlay", ignoreCase = true)) return null

        val mountPoint = parts.getOrNull(4) ?: return null
        val superOpts = parts.getOrNull(dashIdx + 3) ?: ""

        // --- Whitelist: known-legitimate overlay mount point prefixes --------
        val systemOverlayWhitelist = listOf(
            "/apex/",
            "/system/overlay", "/vendor/overlay", "/product/overlay",
            "/system_ext/overlay", "/odm/overlay", "/oem/overlay"
        )
        if (systemOverlayWhitelist.any { mountPoint.startsWith(it) }) return null

        // --- Root-tool path markers in lowerdir / upperdir -------------------
        val rootToolPathMarkers = listOf(
            "/data/adb/", "/magisk/", "/sbin/.core", "@ksu",
            "/data/local/tmp/magisk", "worker/upper/data"
        )
        if (rootToolPathMarkers.any { superOpts.contains(it, ignoreCase = true) }) {
            return "$mountPoint (lowerdir contains root-tool path)"
        }

        // --- Overlay on a system partition with a non-system lowerdir --------
        // Magisk mounts modules as overlays on top of /system, /vendor, /product.
        // The lowerdir on a clean device only references read-only system paths;
        // if it contains /data or other writable-partition paths, that is suspicious.
        val systemMountPrefixes = listOf("/system", "/vendor", "/product", "/sbin", "/odm")
        if (systemMountPrefixes.any { mountPoint == it || mountPoint.startsWith("$it/") }) {
            val lowerDirValue = superOpts
                .split(",")
                .firstOrNull { it.startsWith("lowerdir=") }
                ?.removePrefix("lowerdir=") ?: ""
            // If any lowerdir component is outside the read-only system partitions,
            // it has likely been injected by a root framework.
            val suspiciousLower = lowerDirValue.split(":").any { component ->
                component.isNotEmpty() &&
                    !component.startsWith("/system") &&
                    !component.startsWith("/vendor") &&
                    !component.startsWith("/product") &&
                    !component.startsWith("/odm") &&
                    !component.startsWith("/apex")
            }
            if (suspiciousLower) {
                return "$mountPoint (non-system lowerdir: ${lowerDirValue.take(80)})"
            }
        }

        return null
    }

    // -------------------------------------------------------------------------
    // Luna: roots
    // Checks existence of root binary files and /data/adb root framework dirs.
    // -------------------------------------------------------------------------
    private fun checkRootFiles(): DetectionResult {
        val rootPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/system/xbin/busybox",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
            "/sbin/su", "/su/bin/su", "/su/bin/busybox", "/system/su",
            "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
            "/data/adb/magisk", "/data/adb/ksu", "/data/adb/apatch",
            "/data/adb/su", "/data/adb/magisk.img", "/magisk/.core/bin/su"
        )
        val found = rootPaths.filter { File(it).exists() }

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_root_files",
                name = "Root Binary / Framework Files Detected",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Root-related files found on the filesystem.",
                detailedReason = "Luna-method (roots): Root files found: ${found.joinToString(", ")}.",
                solution = "Remove root tools to eliminate these files.",
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_root_files",
                name = "Root Binary / Framework Files",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No root files found in standard locations.",
                detailedReason = "Luna-method (roots): No root-related files found in common paths.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: kernels / kerneltests
    // Reads /proc/version for custom-kernel strings (kali, KernelSU, topjohnwu…)
    // and /proc/cmdline for unlocked-boot parameters.
    // -------------------------------------------------------------------------
    private fun checkKernelVersion(): DetectionResult {
        val suspiciousStrings = listOf(
            "kali", "parrot", "nethunter", "katzh", "magisk", "kernelsu", "ksu", "topjohnwu"
        )
        val found = mutableListOf<String>()

        try {
            val version = File("/proc/version")
            if (version.canRead()) {
                val text = version.readText().trim()
                for (s in suspiciousStrings) {
                    if (text.contains(s, ignoreCase = true)) found.add("'$s' in /proc/version")
                }
            }
        } catch (_: Exception) {}

        try {
            val cmdline = File("/proc/cmdline")
            if (cmdline.canRead()) {
                val content = cmdline.readText().trim()
                if (content.contains("androidboot.verifiedbootstate=orange") ||
                    content.contains("androidboot.flash.locked=0") ||
                    content.contains("skip_initramfs")
                ) {
                    found.add("boot cmdline: unlocked/custom boot (${content.take(120)})")
                }
            }
        } catch (_: Exception) {}

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_kernel_version",
                name = "Custom / Rooted Kernel Detected",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Kernel version or boot parameters indicate a custom/modified kernel.",
                detailedReason = "Luna-method (kernels): ${found.joinToString("; ")}. " +
                    "A custom kernel (e.g. KernelSU-patched) is required for kernel-level rooting.",
                solution = "Restore the stock kernel via Fastboot or supported recovery.",
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_kernel_version",
                name = "Kernel Version Check",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Kernel version appears standard.",
                detailedReason = "Luna-method (kernels): /proc/version contains no custom-kernel indicators.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: findauth
    // access("/data/local/tmp/attestation") → exists means root is present.
    // Root tools create this file as an authorization/attestation marker.
    // -------------------------------------------------------------------------
    private fun checkAttestationFile(): DetectionResult {
        val path = "/data/local/tmp/attestation"
        val exists = File(path).exists()

        return if (exists) {
            DetectionResult(
                id = "luna_attestation_file",
                name = "Root Attestation File Detected",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Root attestation test file found at $path.",
                detailedReason = "Luna-method (findauth): access($path) succeeded. " +
                    "Root tools create this file as an authorization/attestation marker.",
                solution = "Remove the file with root: `rm $path`.",
                technicalDetail = "File exists: $path"
            )
        } else {
            DetectionResult(
                id = "luna_attestation_file",
                name = "Root Attestation File",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No root attestation file found.",
                detailedReason = "Luna-method (findauth): $path does not exist.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: getEvilModules
    // Scans /system/lib*, /vendor/lib*, /data/adb for known root native library
    // files (libmagiskinit.so, libzygisk.so, liblspd.so…).
    // Also checks /proc/self/maps for in-process loaded root libraries.
    // -------------------------------------------------------------------------
    private fun checkEvilModules(): DetectionResult {
        val evilLibs = setOf(
            "libmagiskinit.so", "libzygisk.so", "liblspd.so", "libxposed_art.so",
            "libriru.so", "librirud.so", "libksu.so", "libapatch.so",
            "libzygisk_ptrace.so", "libzygisk_loader.so", "libshamiko.so"
        )
        val searchDirs = listOf(
            "/system/lib", "/system/lib64", "/system/lib/modules",
            "/vendor/lib", "/vendor/lib64", "/data/adb"
        )
        val found = mutableListOf<String>()

        for (dir in searchDirs) {
            val d = File(dir)
            if (!d.isDirectory) continue
            try {
                val files = d.listFiles() ?: continue
                for (f in files) {
                    if (evilLibs.contains(f.name.lowercase()) && !found.contains("$dir/${f.name}")) {
                        found.add("$dir/${f.name}")
                    }
                }
            } catch (_: Exception) {}
        }

        try {
            val maps = File("/proc/self/maps")
            if (maps.canRead()) {
                val content = maps.readText()
                for (lib in evilLibs) {
                    if (content.contains(lib, ignoreCase = true) && found.none { it.contains(lib) }) {
                        found.add("loaded in process: $lib")
                    }
                }
            }
        } catch (_: Exception) {}

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_evil_modules",
                name = "Root Native Modules Detected",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Known root framework native libraries detected.",
                detailedReason = "Luna-method (getEvilModules): Found: ${found.joinToString(", ")}. " +
                    "libmagiskinit.so / libzygisk.so / liblspd.so are core root-framework components.",
                solution = "Uninstall the associated root framework.",
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_evil_modules",
                name = "Root Native Modules",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No known root native module files detected.",
                detailedReason = "Luna-method (getEvilModules): No known root native libraries found.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: getapps / getDeviceIdentifiers
    // Checks PackageManager for known root manager and hook-framework packages.
    // -------------------------------------------------------------------------
    private fun checkInstalledRootApps(): DetectionResult {
        val rootPackages = listOf(
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu",
            "me.bmax.apatch",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "com.koushikdutta.superuser",
            "com.yellowes.su",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "de.robv.android.xposed.installer",
            "io.github.lsposed.manager",
            "org.meowcat.edxposed.manager",
            "me.weishu.exp",
            "com.saurik.substrate",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus"
        )
        val found = rootPackages.filter { packageExists(it) }

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_root_apps",
                name = "Root Management Apps Detected",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Known root manager or hook framework apps are installed.",
                detailedReason = "Luna-method (getapps): Installed root packages: ${found.joinToString(", ")}.",
                solution = "Uninstall these applications to remove root indicators.",
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_root_apps",
                name = "Root Management Apps",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No known root management apps detected.",
                detailedReason = "Luna-method (getapps): No known root manager or hook framework packages installed.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: findapply
    // Checks enabled accessibility services for known automation/scripting tools
    // (Auto.js, AutoX.js…) commonly used with root for automated cheating.
    // -------------------------------------------------------------------------
    private fun checkAccessibilityServices(): DetectionResult {
        val suspiciousPatterns = listOf(
            "youhu.laixijs", "autojs", "autox", "autoxjs",
            "com.stardust", "org.autojs", "com.zhuhailong.autojs",
            "scene", "mt.manager"
        )
        val found = mutableListOf<String>()

        try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
            val services = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            for (svc in services) {
                val id = svc.id.lowercase()
                for (pattern in suspiciousPatterns) {
                    if (id.contains(pattern.lowercase())) {
                        found.add(svc.id)
                        break
                    }
                }
            }
        } catch (_: Exception) {}

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_accessibility_svc",
                name = "Automation Tool in Accessibility Services",
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "Known root-automation tools are active as accessibility services.",
                detailedReason = "Luna-method (findapply): Found suspicious accessibility services: " +
                    "${found.joinToString(", ")}. " +
                    "Auto.js and similar tools use accessibility APIs for root-based automation.",
                solution = "Disable the listed accessibility services in Settings.",
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_accessibility_svc",
                name = "Accessibility Service Check",
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "No suspicious accessibility services detected.",
                detailedReason = "Luna-method (findapply): No known automation tools found in enabled accessibility services.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: findbootbl / checkbootbl / bootloaders
    // Checks ro.boot.verifiedbootstate, ro.boot.flash.locked, and
    // ro.boot.vbmeta.device_state to detect an unlocked bootloader.
    // -------------------------------------------------------------------------
    private fun checkBootloaderUnlocked(): DetectionResult {
        val indicators = mutableListOf<String>()

        val verifiedBootState = getSystemProperty("ro.boot.verifiedbootstate")
        if (verifiedBootState.isNotEmpty() && verifiedBootState != "green") {
            indicators.add("ro.boot.verifiedbootstate=$verifiedBootState (expected: green)")
        }
        val flashLocked = getSystemProperty("ro.boot.flash.locked")
        if (flashLocked == "0") {
            indicators.add("ro.boot.flash.locked=0 (unlocked)")
        }
        val vbmetaState = getSystemProperty("ro.boot.vbmeta.device_state")
        if (vbmetaState == "unlocked") {
            indicators.add("ro.boot.vbmeta.device_state=unlocked")
        }

        return if (indicators.isNotEmpty()) {
            DetectionResult(
                id = "luna_bootloader",
                name = "Bootloader Unlocked",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "System properties indicate an unlocked bootloader.",
                detailedReason = "Luna-method (findbootbl): ${indicators.joinToString("; ")}. " +
                    "An unlocked bootloader is a prerequisite for flashing root frameworks.",
                solution = "Re-lock the bootloader via the manufacturer's official procedure.",
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_bootloader",
                name = "Bootloader Status",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Bootloader appears to be locked.",
                detailedReason = "Luna-method (findbootbl): Boot properties indicate a locked, verified bootloader.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: checknum
    // __system_property_get("persist.sys.vold_app_data_isolation") → "0" means
    // vold data isolation has been disabled by a root tool.
    // -------------------------------------------------------------------------
    private fun checkVoldIsolationProperty(): DetectionResult {
        val prop = getSystemProperty("persist.sys.vold_app_data_isolation")
        val disabled = prop == "0"

        return if (disabled) {
            DetectionResult(
                id = "luna_vold_isolation",
                name = "Vold Data Isolation Disabled",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "persist.sys.vold_app_data_isolation is set to 0 (disabled).",
                detailedReason = "Luna-method (checknum): persist.sys.vold_app_data_isolation=0. " +
                    "Root tools disable vold app data isolation to gain cross-app storage access.",
                solution = "Re-enable storage data isolation; uninstall root tools that modify this property.",
                technicalDetail = "persist.sys.vold_app_data_isolation=$prop"
            )
        } else {
            DetectionResult(
                id = "luna_vold_isolation",
                name = "Vold Data Isolation",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "Vold data isolation property is not disabled.",
                detailedReason = "Luna-method (checknum): persist.sys.vold_app_data_isolation=" +
                    prop.ifEmpty { "(not set)" } + ". Not disabled by root tools.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: scanlib
    // Uses PackageManager to iterate all installed apps, obtains nativeLibraryDir
    // for each, and scans the directory for known root-framework .so files.
    // -------------------------------------------------------------------------
    private fun checkNativeLibraryScan(): DetectionResult {
        val evilLibs = setOf(
            "libmagiskinit.so", "libzygisk.so", "liblspd.so", "libxposed_art.so",
            "libriru.so", "librirud.so", "libksu.so", "libapatch.so",
            "libzygisk_ptrace.so", "libzygisk_loader.so", "libshamiko.so"
        )
        val found = mutableListOf<String>()

        try {
            val apps = context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            for (app in apps) {
                val nativeDir = app.nativeLibraryDir ?: continue
                val dir = File(nativeDir)
                if (!dir.isDirectory) continue
                val files = dir.list() ?: continue
                for (file in files) {
                    if (evilLibs.contains(file.lowercase())) {
                        found.add("${app.packageName}: $file")
                    }
                }
            }
        } catch (_: Exception) {}

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_scanlib",
                name = "Root Native Libraries in App Dirs",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Root framework native libraries found in installed app native-library directories.",
                detailedReason = "Luna-method (scanlib): Found suspicious modules: ${found.joinToString(", ")}.",
                solution = "Uninstall the associated app / root framework.",
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_scanlib",
                name = "Native Library Scan",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No root native libraries found in any installed app directory.",
                detailedReason = "Luna-method (scanlib): No known root .so files found in nativeLibraryDir of any app.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: wNxM8s / K0ajGz / KKajGz
    // Checks for HideMyAppList, TaiChi, and similar root-concealment apps that
    // hide root-manager packages from package-name-based detection.
    // -------------------------------------------------------------------------
    private fun checkSensitivePackagesPresence(): DetectionResult {
        val sensitivePackages = listOf(
            "com.tsng.hidemyapplist",
            "com.tsng.hidemyapplist2",
            "me.weishu.exp",               // TaiChi / 太极
            "io.virtualsoftware.taichi",
            "com.coderstory.toolkit",       // Scene / 场景
            "org.lsposed.manager",
            "com.zhenxi.hunter"
        )
        val found = sensitivePackages.filter { packageExists(it) }

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_sensitive_pkgs",
                name = "Root-Hiding / Bypass Apps Detected",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Apps designed to hide root presence or bypass detection are installed.",
                detailedReason = "Luna-method (wNxM8s/K0ajGz): Found packages: ${found.joinToString(", ")}. " +
                    "HideMyAppList and TaiChi conceal root-manager packages from app-level detection.",
                solution = "Uninstall these apps.",
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_sensitive_pkgs",
                name = "Root-Hiding / Bypass Apps",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No root-hiding apps detected.",
                detailedReason = "Luna-method (wNxM8s/K0ajGz): No known root-hiding packages installed.",
                solution = "No action required."
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: magiskmac
    // Reads /sys/class/net/<iface>/address to detect a zero MAC address
    // (00:00:00:00:00:00) which indicates Magisk or root modules are suppressing
    // or spoofing the hardware MAC to bypass device fingerprinting.
    // -------------------------------------------------------------------------
    private fun checkMacAddressAnomaly(): DetectionResult {
        val suspicious = mutableListOf<String>()

        try {
            val netDir = File("/sys/class/net")
            val ifaces = netDir.listFiles() ?: emptyArray()
            for (iface in ifaces) {
                if (iface.name == "lo") continue
                val addressFile = File(iface, "address")
                if (!addressFile.canRead()) continue
                val mac = addressFile.readText().trim()
                if (mac == "00:00:00:00:00:00") {
                    suspicious.add("${iface.name}: zero MAC — possible root spoofing")
                }
            }
        } catch (_: Exception) {}

        return if (suspicious.isNotEmpty()) {
            DetectionResult(
                id = "luna_mac_anomaly",
                name = "MAC Address Anomaly (Zero MAC)",
                category = DetectionCategory.NETWORK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "Network interface has a zero MAC address, indicating possible root spoofing.",
                detailedReason = "Luna-method (magiskmac): ${suspicious.joinToString("; ")}. " +
                    "Magisk or root modules may suppress the MAC address to bypass device fingerprinting.",
                solution = "Investigate whether a Magisk module is suppressing MAC addresses.",
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_mac_anomaly",
                name = "MAC Address Check",
                category = DetectionCategory.NETWORK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "No zero MAC address anomalies detected.",
                detailedReason = "Luna-method (magiskmac): All readable network interfaces have non-zero MAC addresses.",
                solution = "No action required."
            )
        }
    }

    // ---- Utilities ----------------------------------------------------------

    private fun packageExists(packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    private fun getSystemProperty(key: String): String {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
            BufferedReader(InputStreamReader(process.inputStream)).readLine()?.trim() ?: ""
        } catch (_: Exception) {
            ""
        }
    }
}
