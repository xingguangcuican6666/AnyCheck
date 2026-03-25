package com.anycheck.app.detection

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.PackageManager
import android.view.accessibility.AccessibilityManager
import com.anycheck.app.R
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
                name = context.getString(R.string.chk_luna_lsp_prop_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_lsp_prop_desc),
                detailedReason = context.getString(R.string.chk_luna_lsp_prop_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_lsp_prop_solution),
                technicalDetail = "Props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "luna_lsp_prop",
                name = context.getString(R.string.chk_luna_lsp_prop_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_lsp_prop_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_lsp_prop_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_ksu_daemon_name),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_ksu_daemon_desc),
                detailedReason = context.getString(R.string.chk_luna_ksu_daemon_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_ksu_daemon_solution),
                technicalDetail = "Service props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "luna_ksu_daemon",
                name = context.getString(R.string.chk_luna_ksu_daemon_name),
                category = DetectionCategory.KERNELSU,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_ksu_daemon_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_ksu_daemon_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_magisk_svc_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_magisk_svc_desc),
                detailedReason = context.getString(R.string.chk_luna_magisk_svc_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_magisk_svc_solution),
                technicalDetail = "Service props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "luna_magisk_svc_prop",
                name = context.getString(R.string.chk_luna_magisk_svc_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_magisk_svc_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_magisk_svc_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_path_su_name),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_path_su_desc),
                detailedReason = context.getString(R.string.chk_luna_path_su_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_path_su_solution),
                technicalDetail = "Found in PATH: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "luna_path_su",
                name = context.getString(R.string.chk_luna_path_su_name),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_path_su_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_path_su_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_apatch_proc_name),
                category = DetectionCategory.APATCH,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_apatch_proc_desc),
                detailedReason = context.getString(R.string.chk_luna_apatch_proc_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_apatch_proc_solution),
                technicalDetail = "Processes: ${found.joinToString("; ")}; total procs scanned: $procCount"
            )
        } else {
            DetectionResult(
                id = "luna_apatch_proc",
                name = context.getString(R.string.chk_luna_apatch_proc_name_nd),
                category = DetectionCategory.APATCH,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_apatch_proc_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_apatch_proc_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_file_size_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_luna_file_size_desc),
                detailedReason = context.getString(R.string.chk_luna_file_size_reason, suspicious.joinToString("; ")),
                solution = context.getString(R.string.chk_luna_file_size_solution),
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_file_size",
                name = context.getString(R.string.chk_luna_file_size_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_luna_file_size_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_file_size_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_kernel_stat_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_kernel_stat_desc),
                detailedReason = context.getString(R.string.chk_luna_kernel_stat_reason, suspicious.joinToString("; ")),
                solution = context.getString(R.string.chk_luna_kernel_stat_solution),
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_kernel_stat",
                name = context.getString(R.string.chk_luna_kernel_stat_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_kernel_stat_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_kernel_stat_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_magisk_mounts_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_magisk_mounts_desc),
                detailedReason = context.getString(R.string.chk_luna_magisk_mounts_reason, suspicious.joinToString("; ")),
                solution = context.getString(R.string.chk_luna_magisk_mounts_solution),
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_magisk_mounts",
                name = context.getString(R.string.chk_luna_magisk_mounts_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_magisk_mounts_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_magisk_mounts_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_zygote_inject_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_zygote_inject_desc),
                detailedReason = context.getString(R.string.chk_luna_zygote_inject_reason, suspicious.joinToString("; ")),
                solution = context.getString(R.string.chk_luna_zygote_inject_solution),
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_zygote_inject",
                name = context.getString(R.string.chk_luna_zygote_inject_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_zygote_inject_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_zygote_inject_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_tmpfs_mount_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_tmpfs_mount_desc),
                detailedReason = context.getString(R.string.chk_luna_tmpfs_mount_reason, suspicious.joinToString("; ")),
                solution = context.getString(R.string.chk_luna_tmpfs_mount_solution),
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_tmpfs_mount",
                name = context.getString(R.string.chk_luna_tmpfs_mount_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_tmpfs_mount_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_tmpfs_mount_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_procscan_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_luna_procscan_desc),
                detailedReason = context.getString(R.string.chk_luna_procscan_reason, all.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_procscan_solution),
                technicalDetail = all.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_procscan",
                name = context.getString(R.string.chk_luna_procscan_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_procscan_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_procscan_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_root_files_name),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_root_files_desc),
                detailedReason = context.getString(R.string.chk_luna_root_files_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_root_files_solution),
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_root_files",
                name = context.getString(R.string.chk_luna_root_files_name_nd),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_root_files_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_root_files_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_kernel_version_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_kernel_version_desc),
                detailedReason = context.getString(R.string.chk_luna_kernel_version_reason, found.joinToString("; ")),
                solution = context.getString(R.string.chk_luna_kernel_version_solution),
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_kernel_version",
                name = context.getString(R.string.chk_luna_kernel_version_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_kernel_version_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_kernel_version_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_attestation_file_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_attestation_file_desc),
                detailedReason = context.getString(R.string.chk_luna_attestation_file_reason),
                solution = context.getString(R.string.chk_luna_attestation_file_solution),
                technicalDetail = "File exists: $path"
            )
        } else {
            DetectionResult(
                id = "luna_attestation_file",
                name = context.getString(R.string.chk_luna_attestation_file_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_attestation_file_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_attestation_file_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_evil_modules_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_evil_modules_desc),
                detailedReason = context.getString(R.string.chk_luna_evil_modules_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_evil_modules_solution),
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_evil_modules",
                name = context.getString(R.string.chk_luna_evil_modules_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_evil_modules_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_evil_modules_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_root_apps_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_root_apps_desc),
                detailedReason = context.getString(R.string.chk_luna_root_apps_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_root_apps_solution),
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_root_apps",
                name = context.getString(R.string.chk_luna_root_apps_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_root_apps_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_root_apps_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_accessibility_svc_name),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_luna_accessibility_svc_desc),
                detailedReason = context.getString(R.string.chk_luna_accessibility_svc_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_accessibility_svc_solution),
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_accessibility_svc",
                name = context.getString(R.string.chk_luna_accessibility_svc_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_luna_accessibility_svc_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_accessibility_svc_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_bootloader_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_bootloader_desc),
                detailedReason = context.getString(R.string.chk_luna_bootloader_reason, indicators.joinToString("; ")),
                solution = context.getString(R.string.chk_luna_bootloader_solution),
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_bootloader",
                name = context.getString(R.string.chk_luna_bootloader_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_bootloader_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_bootloader_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_vold_isolation_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_luna_vold_isolation_desc),
                detailedReason = context.getString(R.string.chk_luna_vold_isolation_reason),
                solution = context.getString(R.string.chk_luna_vold_isolation_solution),
                technicalDetail = "persist.sys.vold_app_data_isolation=$prop"
            )
        } else {
            DetectionResult(
                id = "luna_vold_isolation",
                name = context.getString(R.string.chk_luna_vold_isolation_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_luna_vold_isolation_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_vold_isolation_reason_nd, prop.ifEmpty { "(not set)" }),
                solution = context.getString(R.string.no_action_required)
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
                name = context.getString(R.string.chk_luna_scanlib_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_scanlib_desc),
                detailedReason = context.getString(R.string.chk_luna_scanlib_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_scanlib_solution),
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_scanlib",
                name = context.getString(R.string.chk_luna_scanlib_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_luna_scanlib_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_scanlib_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
            "org.lsposed.manager"
        )
        val found = sensitivePackages.filter { packageExists(it) }

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "luna_sensitive_pkgs",
                name = context.getString(R.string.chk_luna_sensitive_pkgs_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_sensitive_pkgs_desc),
                detailedReason = context.getString(R.string.chk_luna_sensitive_pkgs_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_luna_sensitive_pkgs_solution),
                technicalDetail = found.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_sensitive_pkgs",
                name = context.getString(R.string.chk_luna_sensitive_pkgs_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_luna_sensitive_pkgs_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_sensitive_pkgs_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Luna: magiskmac
    //
    // Reverse-engineered from Luna libluna.so "magiskmac" method.
    // Reference log (API 36 device):
    //   magiskmac: 接口 dummy0 的MAC地址: c6:53:53:28:9d:fe
    //   magiskmac: 接口 dummy0 MAC地址全零检查:  否
    //   magiskmac: 在Android 11+上检测到MAC地址，存在风险
    //
    // Luna enumerates interfaces via netlink and applies TWO rules:
    //
    //  Rule A (all API levels): Zero MAC (00:00:00:00:00:00)
    //        Magisk creates virtual network interfaces in isolated namespaces;
    //        these sometimes appear with all-zero MACs.
    //
    //  Rule B (Android 11+ / API ≥ 30 only): dummy0 interface with ANY non-zero MAC
    //        On Android 11+, stock devices do not have a dummy0 interface.
    //        Magisk's DenyList isolation creates a dummy0 interface in the network
    //        namespace; even with a randomised MAC the mere presence of dummy0 is
    //        the risk signal that Luna reports.
    //
    //  Rule C (all API levels): WiFi MAC vs hardware property mismatch
    //        Magisk MAC-spoofing modules change /sys/class/net/wlan0/address but
    //        leave the hardware MAC in Android system properties.
    //
    // We use NetworkInterface.getNetworkInterfaces() as the enumeration source
    // because it internally uses netlink — matching Luna's behaviour — and also
    // fall back to /sys/class/net for interfaces that may be hidden.
    // -------------------------------------------------------------------------
    private fun checkMacAddressAnomaly(): DetectionResult {
        val suspicious = mutableListOf<String>()
        val apiLevel = android.os.Build.VERSION.SDK_INT

        // --- Rule A & B: enumerate interfaces via NetworkInterface (netlink) ---
        try {
            val niEnum = java.net.NetworkInterface.getNetworkInterfaces()
            while (niEnum != null && niEnum.hasMoreElements()) {
                val ni = niEnum.nextElement()
                val name = ni.name ?: continue
                if (name == "lo") continue          // skip loopback

                val macBytes = runCatching { ni.hardwareAddress }.getOrNull()
                val mac = if (macBytes != null && macBytes.size == 6) {
                    macBytes.joinToString(":") { "%02x".format(it) }
                } else {
                    // fall back to /sys/class/net if JNI returned null
                    runCatching {
                        File("/sys/class/net/$name/address").readText().trim()
                    }.getOrDefault("")
                }

                // Rule A: zero MAC on any interface
                if (mac == "00:00:00:00:00:00") {
                    suspicious.add("$name: zero MAC (00:00:00:00:00:00) — Magisk vnet artifact [Rule A]")
                    continue
                }

                // Rule B: on Android 11+, any dummy* interface with non-zero MAC is suspicious
                if (apiLevel >= android.os.Build.VERSION_CODES.R &&
                    name.startsWith("dummy")
                ) {
                    suspicious.add(
                        "$name: dummy interface present on Android 11+ (mac=$mac)" +
                            " — Magisk DenyList network namespace [Rule B, API=$apiLevel]"
                    )
                    continue
                }

                // For older Android: also flag dummy/vnet with placeholder MACs
                if (apiLevel < android.os.Build.VERSION_CODES.R &&
                    (name.startsWith("dummy") || name.startsWith("vnet"))
                ) {
                    if (mac == "02:00:00:00:00:00") {
                        suspicious.add(
                            "$name: virtual interface with placeholder MAC ($mac)" +
                                " — Magisk namespace artifact [legacy, API=$apiLevel]"
                        )
                    }
                }
            }
        } catch (_: Exception) {
            // Fallback: read directly from /sys/class/net
            try {
                val netDir = File("/sys/class/net")
                val ifaces = netDir.listFiles() ?: emptyArray()
                for (iface in ifaces) {
                    if (iface.name == "lo") continue
                    val mac = runCatching {
                        File(iface, "address").readText().trim()
                    }.getOrNull() ?: continue
                    if (mac == "00:00:00:00:00:00") {
                        suspicious.add("${iface.name}: zero MAC — Magisk vnet artifact [Rule A, sysfs]")
                    } else if (apiLevel >= android.os.Build.VERSION_CODES.R &&
                        (iface.name == "dummy0" || iface.name.startsWith("dummy"))
                    ) {
                        suspicious.add(
                            "${iface.name}: dummy interface present on Android 11+ (mac=$mac)" +
                                " [Rule B, sysfs, API=$apiLevel]"
                        )
                    }
                }
            } catch (_: Exception) {}
        }

        // --- Rule C: WiFi MAC vs hardware-MAC system-property mismatch ---
        // Magisk MAC-spoofing modules alter /sys/class/net/wlan0/address but leave
        // the device's factory MAC address in the system property store intact.
        runCatching {
            val wlanFile = File("/sys/class/net/wlan0/address")
            if (!wlanFile.exists() || !wlanFile.canRead()) return@runCatching
            val wlanMac = wlanFile.readText().trim()
            if (wlanMac.isNotEmpty() && wlanMac != "00:00:00:00:00:00") {
                val sp = Class.forName("android.os.SystemProperties")
                val getProp = sp.getMethod("get", String::class.java, String::class.java)
                listOf(
                    "ro.boot.mac_addr",
                    "ro.boot.wifimacaddr",
                    "persist.sys.wifi_mac",
                    "wifi.mac.addr"
                ).forEach { prop ->
                    val hwMac = (getProp.invoke(null, prop, "") as? String)
                        ?.trim()?.lowercase()
                    if (!hwMac.isNullOrEmpty() &&
                        hwMac != wlanMac.lowercase() &&
                        hwMac != "00:00:00:00:00:00"
                    ) {
                        suspicious.add(
                            "wlan0 MAC mismatch: current=$wlanMac vs hw[$prop]=$hwMac" +
                                " — possible MAC spoofing [Rule C]"
                        )
                    }
                }
            }
        }

        return if (suspicious.isNotEmpty()) {
            DetectionResult(
                id = "luna_mac_anomaly",
                name = context.getString(R.string.chk_luna_mac_anomaly_name),
                category = DetectionCategory.NETWORK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_luna_mac_anomaly_desc),
                detailedReason = context.getString(R.string.chk_luna_mac_anomaly_reason, suspicious.joinToString("; ")),
                solution = context.getString(R.string.chk_luna_mac_anomaly_solution),
                technicalDetail = "API=$apiLevel; " + suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_mac_anomaly",
                name = context.getString(R.string.chk_luna_mac_anomaly_name_nd),
                category = DetectionCategory.NETWORK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_luna_mac_anomaly_desc_nd),
                detailedReason = context.getString(R.string.chk_luna_mac_anomaly_reason_nd),
                solution = context.getString(R.string.no_action_required)
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
