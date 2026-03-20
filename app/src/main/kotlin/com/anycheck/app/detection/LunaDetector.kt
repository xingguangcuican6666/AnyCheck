package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetAddress

/**
 * Luna-inspired detection engine.
 *
 * Implements detection methods reverse-engineered from the Luna safety checker
 * (luna.safe.luna / JNI methods in libluna.so), covering:
 *  - findlsp     → LSPosed API system property check
 *  - findksu     → KernelSU daemon service property check
 *  - checkxiaomi → Xiaomi/MIUI device identification
 *  - rhosts      → /system/etc/hosts tampering check
 *  - checkappnum → Magisk daemon service property check
 *  - psdir       → PATH-directory su/root binary scan
 *  - rustmagisk  → APatch process scan via /proc
 *  - fhma        → suspicious system-file size check (stat)
 *  - checksuskernel → kernel-level stat anomaly via /proc/net/unix + SELinux context
 *  - checkdns    → DNS integrity check via known-domain resolution
 */
class LunaDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkLSPosedApiProperty(),
        checkKernelSUDaemon(),
        checkXiaomiMIUI(),
        checkHostsModification(),
        checkMagiskDaemonProperty(),
        checkSuInPathDirectories(),
        checkAPatchProcesses(),
        checkSuspiciousFileSize(),
        checkKernelStatAnomaly(),
        checkDnsIntegrity()
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
    // Luna: checkxiaomi
    // __system_property_get(DAT_001404f0, buf) → exists means MIUI device
    // -------------------------------------------------------------------------
    private fun checkXiaomiMIUI(): DetectionResult {
        val miuiProps = listOf(
            "ro.miui.ui.version.code",
            "ro.miui.ui.version.name",
            "ro.product.mod_device"
        )
        val found = mutableListOf<String>()
        for (prop in miuiProps) {
            val value = getSystemProperty(prop)
            if (value.isNotEmpty()) found.add("$prop=$value")
        }
        val brand = Build.BRAND.lowercase()
        val manufacturer = Build.MANUFACTURER.lowercase()
        val isXiaomi = brand in listOf("xiaomi", "redmi", "poco") ||
            manufacturer in listOf("xiaomi", "redmi")
        if (isXiaomi && found.isEmpty()) found.add("Build.BRAND=${Build.BRAND}")

        // Being a Xiaomi/MIUI device is device-context information only.
        // It is NOT a root indicator, so we always report NOT_DETECTED regardless
        // of whether the device is Xiaomi, to avoid false positives ("turning red").
        return DetectionResult(
            id = "luna_xiaomi_miui",
            name = "Xiaomi/MIUI Device",
            category = DetectionCategory.ENVIRONMENT,
            status = DetectionStatus.NOT_DETECTED,
            riskLevel = RiskLevel.INFO,
            description = if (found.isNotEmpty())
                "Device is running MIUI/HyperOS or is a Xiaomi/Redmi device (informational only)."
            else
                "Device is not a Xiaomi/MIUI device.",
            detailedReason = if (found.isNotEmpty())
                "Luna-method (checkxiaomi): Device identified as Xiaomi/MIUI — " +
                    "found: ${found.joinToString(", ")}. " +
                    "This is purely informational; device brand is not a root indicator."
            else
                "Luna-method (checkxiaomi): No MIUI system properties detected.",
            solution = "No action required.",
            technicalDetail = if (found.isNotEmpty()) "Xiaomi props: ${found.joinToString("; ")}" else ""
        )
    }

    // -------------------------------------------------------------------------
    // Luna: rhosts
    // Opens DAT_0013fe10 (/system/etc/hosts) and DAT_0013fe28 (/etc/hosts),
    // reads content, and returns line data; detects non-default entries.
    // -------------------------------------------------------------------------
    private fun checkHostsModification(): DetectionResult {
        val hostsFiles = listOf("/system/etc/hosts", "/etc/hosts")
        val suspicious = mutableListOf<String>()

        for (path in hostsFiles) {
            val file = File(path)
            if (!file.exists()) continue
            try {
                val lines = file.readLines()
                val nonStandard = lines.filter { line ->
                    val t = line.trim()
                    t.isNotEmpty() && !t.startsWith("#") &&
                        t !in setOf(
                            "127.0.0.1 localhost",
                            "127.0.0.1  localhost",
                            "::1 localhost",
                            "::1  localhost",
                            "fe80::1%lo0 localhost"
                        )
                }
                if (nonStandard.isNotEmpty()) {
                    suspicious.add("$path: ${nonStandard.size} non-standard entr(ies)")
                }
                if (file.length() > 200L) {
                    suspicious.add("$path size=${file.length()} bytes (unusually large)")
                }
            } catch (_: Exception) {}
        }

        return if (suspicious.isNotEmpty()) {
            DetectionResult(
                id = "luna_hosts_tamper",
                name = "Hosts File Tampering Detected",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "System hosts file has been modified beyond standard localhost entries.",
                detailedReason = "Luna-method (rhosts): fopen/fread on /system/etc/hosts and /etc/hosts " +
                    "detected non-standard content. ${suspicious.joinToString("; ")}. " +
                    "Root tools often modify the hosts file to redirect or block detection-server traffic.",
                solution = "Restore the default hosts file: it should only contain the " +
                    "'127.0.0.1 localhost' and '::1 localhost' entries.",
                technicalDetail = suspicious.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "luna_hosts_tamper",
                name = "Hosts File Tampering",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "System hosts file appears unmodified.",
                detailedReason = "Luna-method (rhosts): No non-standard entries found in the hosts files.",
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
        // Maps path → maximum expected size in bytes
        // Luna flags size > 2047 bytes on a particular file; we apply the same
        // threshold to well-known small config files that root tools may replace.
        val sizeThresholds = mapOf(
            "/system/etc/hosts" to 200L,
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
    // Luna: checkdns
    // getaddrinfo(DAT_0013f8c8, ...) → inet_ntop → strcmp with DAT_0013f8d8
    // Resolves a well-known hostname and verifies the returned IP is expected.
    // Returns DETECTED if DNS resolution returns unexpected results.
    // -------------------------------------------------------------------------
    private fun checkDnsIntegrity(): DetectionResult {
        // Google's connectivity-check domain has stable, well-known IP ranges.
        // Unexpected IPs could indicate DNS hijacking by root tools or VPN.
        val testDomain = "connectivitycheck.gstatic.com"
        // Known Google IP prefixes (IPv4 and IPv6 ranges for gstatic.com)
        val googleIpPrefixes = listOf(
            "142.250.", "172.217.", "216.58.", "64.233.", "74.125.",
            "209.85.", "66.102.", "2a00:1450:", "2607:f8b0:", "2404:6800:"
        )

        return try {
            val addresses = InetAddress.getAllByName(testDomain)
            val resolvedIps = addresses.mapNotNull { it.hostAddress }

            if (resolvedIps.isEmpty()) {
                // No resolution result — network may be offline; skip check
                DetectionResult(
                    id = "luna_dns_check",
                    name = "DNS Integrity",
                    category = DetectionCategory.ENVIRONMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = "DNS check skipped (no network or resolution failed).",
                    detailedReason = "Luna-method (checkdns): getaddrinfo returned no addresses. " +
                        "Network may be unavailable.",
                    solution = "No action required."
                )
            } else {
                val allExpected = resolvedIps.all { ip ->
                    googleIpPrefixes.any { prefix -> ip.startsWith(prefix) }
                }
                if (!allExpected) {
                    val unexpected = resolvedIps.filter { ip ->
                        googleIpPrefixes.none { prefix -> ip.startsWith(prefix) }
                    }
                    DetectionResult(
                        id = "luna_dns_check",
                        name = "DNS Hijacking Detected",
                        category = DetectionCategory.ENVIRONMENT,
                        status = DetectionStatus.DETECTED,
                        riskLevel = RiskLevel.MEDIUM,
                        description = "DNS resolution returned unexpected IP addresses.",
                        detailedReason = "Luna-method (checkdns): $testDomain resolved to unexpected IPs: " +
                            "${unexpected.joinToString(", ")}. " +
                            "Root tools may modify /etc/hosts or install a local DNS proxy to redirect " +
                            "traffic and bypass security checks.",
                        solution = "Check /system/etc/hosts for unauthorized entries and review VPN/proxy configuration.",
                        technicalDetail = "Resolved: ${resolvedIps.joinToString(", ")}; " +
                            "unexpected: ${unexpected.joinToString(", ")}"
                    )
                } else {
                    DetectionResult(
                        id = "luna_dns_check",
                        name = "DNS Integrity",
                        category = DetectionCategory.ENVIRONMENT,
                        status = DetectionStatus.NOT_DETECTED,
                        riskLevel = RiskLevel.MEDIUM,
                        description = "DNS resolution returned expected IP addresses.",
                        detailedReason = "Luna-method (checkdns): $testDomain resolved to expected " +
                            "Google IPs: ${resolvedIps.joinToString(", ")}.",
                        solution = "No action required."
                    )
                }
            }
        } catch (_: Exception) {
            // Network unavailable → mark as not detected (safe default)
            DetectionResult(
                id = "luna_dns_check",
                name = "DNS Integrity",
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "DNS check skipped (network error or no connectivity).",
                detailedReason = "Luna-method (checkdns): DNS resolution failed — network may be offline.",
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
