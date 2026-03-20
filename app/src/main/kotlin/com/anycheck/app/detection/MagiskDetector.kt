package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Comprehensive Magisk detection engine.
 * Implements all known detection methods used by the security community.
 */
class MagiskDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkMagiskFiles(),
        checkMagiskDirectories(),
        checkMagiskDatabase(),
        checkMagiskPackages(),
        checkMagiskSuBinary(),
        checkProcNetUnixSocket(),
        checkMagiskMountPoints(),
        checkMagiskProps(),
        checkZygiskLibrary(),
        checkMagiskHideProps(),
        checkMagiskProcesses(),
        checkMagiskManagerHidden(),
        checkMagiskDevFiles(),
        checkZygiskActiveInMaps(),
        checkMagiskStubApp(),
        checkMagiskSELinuxContext(),
        checkMagiskApexOverlay(),
        checkMagiskFileDescriptors(),
        checkNativeBridgeInjection(),
        checkZygiskSUDaemon(),
        checkMagiskTimingLatency(),
        checkBroaderMapsPatterns()
    )

    /** Check 1: Known Magisk-specific files */
    private fun checkMagiskFiles(): DetectionResult {
        val magiskFiles = listOf(
            "/sbin/.magisk",
            "/sbin/.core/mirror",
            "/sbin/.core/img",
            "/sbin/.core/db-0/magisk.db",
            "/data/adb/magisk",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
            "/data/adb/post-fs-data.d",
            "/data/adb/service.d",
            "/data/adb/modules",
            "/data/adb/modules_update",
            "/cache/.disable_magisk",
            "/dev/.magisk",
            "/dev/.magisk.unblock",
            "/.magisk"
        )

        val found = magiskFiles.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "magisk_files",
                name = "Magisk Files Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Magisk-specific files or directories found on the filesystem.",
                detailedReason = "The following Magisk-specific files were found: ${found.joinToString(", ")}. " +
                    "These files are created by Magisk during installation and runtime. " +
                    "Their presence strongly indicates that Magisk is installed on this device.",
                solution = "To remove Magisk: Open Magisk Manager → Uninstall → Complete Uninstall. " +
                    "Or flash the stock boot.img via fastboot: `fastboot flash boot stock_boot.img`.",
                technicalDetail = "Files found: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_files",
                name = "Magisk Files",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Magisk-specific files detected.",
                detailedReason = "None of the known Magisk file paths were accessible or present.",
                solution = "No action required."
            )
        }
    }

    /** Check 2: Magisk data directories */
    private fun checkMagiskDirectories(): DetectionResult {
        val dirs = listOf(
            "/data/adb/magisk",
            "/data/adb/modules",
            "/data/adb/ksu",
            "/sbin/.magisk/mirror",
            "/sbin/.magisk/block",
            "/sbin/.magisk/worker"
        )
        val found = dirs.filter { File(it).isDirectory }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "magisk_dirs",
                name = "Magisk Directories Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Magisk working directories found.",
                detailedReason = "Directories ${found.joinToString(", ")} exist. " +
                    "Magisk uses /data/adb/magisk as its primary working directory and " +
                    "/data/adb/modules to store installed modules. " +
                    "These are created during Magisk installation.",
                solution = "Uninstall Magisk via Magisk Manager or reflash stock boot image.",
                technicalDetail = "Directories found: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_dirs",
                name = "Magisk Directories",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Magisk working directories found.",
                detailedReason = "Magisk working directories were not found.",
                solution = "No action required."
            )
        }
    }

    /** Check 3: Magisk SQLite database */
    private fun checkMagiskDatabase(): DetectionResult {
        val dbPaths = listOf(
            "/data/adb/magisk.db",
            "/data/adb/magisk/magisk.db",
            "/sbin/.core/db-0/magisk.db"
        )
        val found = dbPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "magisk_db",
                name = "Magisk Database Found",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Magisk SQLite database detected.",
                detailedReason = "The Magisk database (magisk.db) stores policy rules, " +
                    "module configurations, and superuser grant records. " +
                    "Found at: ${found.joinToString(", ")}.",
                solution = "The database will be removed when Magisk is fully uninstalled.",
                technicalDetail = "DB paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_db",
                name = "Magisk Database",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Magisk database not found.",
                detailedReason = "No Magisk SQLite database was found at known locations.",
                solution = "No action required."
            )
        }
    }

    /** Check 4: Magisk app packages */
    private fun checkMagiskPackages(): DetectionResult {
        val magiskPackages = listOf(
            "com.topjohnwu.magisk",           // Official Magisk Manager
            "io.github.vvb2060.magisk",       // Alternative fork
            "com.fox2code.mmm",               // Fox's Magisk Module Manager
            "com.fox2code.mmm.debug",
            "com.fox2code.mmm.canary",
            "com.topjohnwu.magisk.alpha",
            "io.github.huskydg.magisk",       // Delta Magisk
            "io.github.l3gacy.b105e7",        // Another fork
            "io.github.vvb2060.magisk.debug"
        )
        val found = magiskPackages.filter { packageExists(it) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "magisk_packages",
                name = "Magisk App Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Magisk Manager or related apps installed.",
                detailedReason = "The following Magisk-related packages were found: ${found.joinToString(", ")}. " +
                    "These apps are the primary management interface for Magisk. " +
                    "Their presence confirms Magisk installation.",
                solution = "Uninstall via Magisk Manager first (to properly remove root), " +
                    "then uninstall the Magisk Manager app itself.",
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_packages",
                name = "Magisk App Packages",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Magisk Manager packages found.",
                detailedReason = "No known Magisk Manager package names were found installed.",
                solution = "No action required."
            )
        }
    }

    /** Check 5: Magisk su binary locations */
    private fun checkMagiskSuBinary(): DetectionResult {
        val suPaths = listOf(
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/system/sbin/su",
            "/vendor/bin/su",
            "/data/adb/magisk/busybox",
            "/sbin/.magisk/busybox",
            "/data/adb/magisk/magisk64",
            "/data/adb/magisk/magisk32",
            "/data/adb/magisk/magiskpolicy",
            "/data/adb/magisk/magiskinit"
        )
        val found = suPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "magisk_su",
                name = "Magisk SU Binary Found",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Magisk su or core binaries detected.",
                detailedReason = "Magisk installs its su binary and core components to manage root access. " +
                    "Found: ${found.joinToString(", ")}. " +
                    "These binaries handle root permission requests and policy enforcement.",
                solution = "These binaries are removed when Magisk is uninstalled via Magisk Manager → Uninstall.",
                technicalDetail = "Binaries: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_su",
                name = "Magisk SU Binary",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Magisk su or core binaries found.",
                detailedReason = "Magisk core binaries were not found at known paths.",
                solution = "No action required."
            )
        }
    }

    /** Check 6: /proc/net/unix socket detection (Magisk daemon socket) */
    private fun checkProcNetUnixSocket(): DetectionResult {
        val magiskSocketNames = listOf(
            "magisk",
            "@magisk_daemon",
            "@magiskd",
            "magisk_new",
            ".magisk"
        )
        return try {
            val content = File("/proc/net/unix").readText()
            val found = magiskSocketNames.filter { content.contains(it, ignoreCase = true) }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "magisk_unix_socket",
                    name = "Magisk Unix Socket Detected",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "Magisk daemon socket found in /proc/net/unix.",
                    detailedReason = "Magisk runs a background daemon that listens on a Unix socket. " +
                        "The socket name '${found.joinToString(", ")}' was found in /proc/net/unix, " +
                        "indicating the Magisk daemon is currently running.",
                    solution = "The socket disappears when Magisk is uninstalled and the device is rebooted.",
                    technicalDetail = "Socket names found: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "magisk_unix_socket",
                    name = "Magisk Unix Socket",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "No Magisk daemon socket found.",
                    detailedReason = "No Magisk-related socket names were found in /proc/net/unix.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "magisk_unix_socket",
                name = "Magisk Unix Socket",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not read /proc/net/unix.",
                detailedReason = "Access to /proc/net/unix was denied or failed: ${e.message}",
                solution = "This check requires read access to /proc/net/unix."
            )
        }
    }

    /** Check 7: Suspicious mount points added by Magisk */
    private fun checkMagiskMountPoints(): DetectionResult {
        return try {
            val mounts = File("/proc/mounts").readText()
            val suspiciousKeywords = listOf(
                "magisk",
                "/sbin/.magisk",
                "/dev/magisk",
                "worker/mirror",
                "worker/block"
            )
            val found = suspiciousKeywords.filter { mounts.contains(it, ignoreCase = true) }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "magisk_mounts",
                    name = "Magisk Mount Points Detected",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "Magisk-related mount points found in /proc/mounts.",
                    detailedReason = "Magisk uses bind mounts to overlay modified files onto the system " +
                        "without actually modifying the underlying partition. " +
                        "Keywords found: ${found.joinToString(", ")}.",
                    solution = "Mount points are managed by Magisk daemon. They are removed upon uninstallation.",
                    technicalDetail = "Keywords: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "magisk_mounts",
                    name = "Magisk Mount Points",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "No Magisk mount points found.",
                    detailedReason = "No Magisk-specific mount entries found in /proc/mounts.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "magisk_mounts",
                name = "Magisk Mount Points",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not read mount information.",
                detailedReason = "Failed to read /proc/mounts: ${e.message}",
                solution = "Ensure the app has permission to read process filesystem."
            )
        }
    }

    /** Check 8: System properties that indicate Magisk */
    private fun checkMagiskProps(): DetectionResult {
        val suspiciousProps = mapOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0",
            "ro.build.selinux" to "0"
        )
        val found = mutableListOf<String>()
        suspiciousProps.forEach { (key, expectedValue) ->
            val value = getSystemProperty(key)
            if (value == expectedValue) {
                found.add("$key=$value")
            }
        }

        // Also check for Magisk-specific prop
        val magiskVersion = getSystemProperty("ro.magisk.version")
        if (magiskVersion.isNotEmpty()) {
            found.add("ro.magisk.version=$magiskVersion")
        }

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "magisk_props",
                name = "Suspicious System Props",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "Suspicious or Magisk-related system properties found.",
                detailedReason = "The following properties suggest root access or Magisk presence: " +
                    "${found.joinToString(", ")}. " +
                    "ro.debuggable=1 and ro.secure=0 are typical on rooted/debuggable builds. " +
                    "ro.magisk.version is set by Magisk directly.",
                solution = "These properties are set by Magisk or during device rooting. " +
                    "Restore the stock boot image to reset these properties.",
                technicalDetail = "Props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_props",
                name = "Magisk System Properties",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "No suspicious Magisk-related system properties found.",
                detailedReason = "System properties appear to be in their stock configuration.",
                solution = "No action required."
            )
        }
    }

    /** Check 9: Zygisk native library injection */
    private fun checkZygiskLibrary(): DetectionResult {
        val zygiskPaths = listOf(
            "/data/adb/magisk/zygisk",
            "/data/adb/modules/zygisk",
            "/dev/magisk/zygisk",
            "/data/adb/magisk/arm64-v8a/zygisk.so",
            "/data/adb/magisk/armeabi-v7a/zygisk.so",
            "/data/adb/magisk/x86_64/zygisk.so",
            "/data/adb/magisk/x86/zygisk.so"
        )
        val found = zygiskPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "zygisk_lib",
                name = "Zygisk Library Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Zygisk (Magisk in Zygote) library files found.",
                detailedReason = "Zygisk is Magisk's feature that runs in the Zygote process, " +
                    "enabling code injection into every app. " +
                    "Found: ${found.joinToString(", ")}. " +
                    "This allows bypassing many detection methods and enables powerful module functionality.",
                solution = "Disable Zygisk in Magisk settings or fully uninstall Magisk.",
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "zygisk_lib",
                name = "Zygisk Library",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Zygisk library files found.",
                detailedReason = "Zygisk library files were not found. Either Zygisk is disabled or Magisk is not installed.",
                solution = "No action required."
            )
        }
    }

    /** Check 10: MagiskHide / DenyList properties */
    private fun checkMagiskHideProps(): DetectionResult {
        val hideIndicators = listOf(
            "/data/adb/magisk/magiskhide",
            "/sbin/.magisk/magiskhide"
        )
        val found = hideIndicators.filter { File(it).exists() }

        // Also check if device fingerprint was modified
        val fingerprint = getSystemProperty("ro.build.fingerprint")
        val modified = fingerprint.contains("custom", ignoreCase = true) ||
            fingerprint.contains("unofficial", ignoreCase = true) ||
            fingerprint.contains("test-keys", ignoreCase = true)

        return if (found.isNotEmpty() || modified) {
            val reasons = mutableListOf<String>()
            if (found.isNotEmpty()) reasons.add("MagiskHide files: ${found.joinToString(", ")}")
            if (modified) reasons.add("Modified build fingerprint: $fingerprint")
            DetectionResult(
                id = "magisk_hide",
                name = "MagiskHide / Modified Fingerprint",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "MagiskHide artifacts or modified build fingerprint detected.",
                detailedReason = "Evidence: ${reasons.joinToString("; ")}. " +
                    "MagiskHide (or its successor DenyList) attempts to hide Magisk from specific apps. " +
                    "A modified build fingerprint may indicate SafetyNet bypass attempts.",
                solution = "Disable MagiskHide/DenyList in Magisk settings. " +
                    "Use a stock, unmodified build fingerprint. " +
                    "Consider using a Play Integrity fix module carefully.",
                technicalDetail = "Indicators: ${reasons.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_hide",
                name = "MagiskHide / Fingerprint",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No MagiskHide artifacts or fingerprint modifications detected.",
                detailedReason = "No MagiskHide files found and build fingerprint appears unmodified.",
                solution = "No action required."
            )
        }
    }

    /** Check 11: Running processes related to Magisk */
    private fun checkMagiskProcesses(): DetectionResult {
        val magiskProcessNames = listOf("magiskd", "magisk", "magiskpolicy", "zygisk")
        val found = mutableListOf<String>()
        return try {
            val procDir = File("/proc")
            procDir.listFiles()?.forEach { pidDir ->
                if (pidDir.isDirectory && pidDir.name.all { it.isDigit() }) {
                    try {
                        val cmdline = File(pidDir, "cmdline").readText()
                            .replace("\u0000", " ").trim()
                        magiskProcessNames.forEach { name ->
                            if (cmdline.contains(name, ignoreCase = true) && !found.contains(cmdline)) {
                                found.add(cmdline.take(50))
                            }
                        }
                    } catch (_: Exception) {}
                }
            }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "magisk_processes",
                    name = "Magisk Processes Running",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "Magisk-related processes are currently running.",
                    detailedReason = "The following Magisk processes were found running: ${found.joinToString(", ")}. " +
                        "magiskd is the Magisk daemon that manages root requests. " +
                        "These processes confirm Magisk is active on the device.",
                    solution = "Processes will stop after Magisk is uninstalled and device rebooted.",
                    technicalDetail = "Processes: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "magisk_processes",
                    name = "Magisk Processes",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "No Magisk processes found running.",
                    detailedReason = "No Magisk-related process names were found in /proc.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "magisk_processes",
                name = "Magisk Processes",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not enumerate running processes.",
                detailedReason = "Process enumeration failed: ${e.message}",
                solution = "Ensure /proc is accessible."
            )
        }
    }

    /** Check 12: Hidden Magisk Manager (stub APK) */
    private fun checkMagiskManagerHidden(): DetectionResult {
        // When Magisk Manager is hidden, it uses a random package name
        // We can detect this by looking for apps with specific characteristics
        val pm = context.packageManager
        val hiddenIndicators = mutableListOf<String>()

        try {
            val installedApps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            installedApps.forEach { appInfo ->
                try {
                    val appLabel = pm.getApplicationLabel(appInfo).toString()
                    // Hidden Magisk Manager often uses "Settings" as its disguise label
                    // and has specific internal patterns
                    if (appLabel.equals("Magisk", ignoreCase = true) &&
                        appInfo.packageName != "com.topjohnwu.magisk"
                    ) {
                        hiddenIndicators.add("${appInfo.packageName} (label: $appLabel)")
                    }
                } catch (_: Exception) {}
            }
        } catch (e: Exception) {
            return DetectionResult(
                id = "magisk_hidden_manager",
                name = "Hidden Magisk Manager",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.MEDIUM,
                description = "Could not scan for hidden Magisk Manager.",
                detailedReason = "Package scan failed: ${e.message}",
                solution = "Ensure the app has QUERY_ALL_PACKAGES permission."
            )
        }

        return if (hiddenIndicators.isNotEmpty()) {
            DetectionResult(
                id = "magisk_hidden_manager",
                name = "Hidden Magisk Manager Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "An app disguised as Magisk Manager was found.",
                detailedReason = "Magisk Manager can be hidden under a random package name to evade detection. " +
                    "Found potential hidden manager: ${hiddenIndicators.joinToString(", ")}.",
                solution = "Open the app and uninstall Magisk, or use adb to remove the package.",
                technicalDetail = "Indicators: ${hiddenIndicators.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_hidden_manager",
                name = "Hidden Magisk Manager",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "No hidden Magisk Manager detected.",
                detailedReason = "No apps with Magisk Manager characteristics were found under non-standard package names.",
                solution = "No action required."
            )
        }
    }

    /** Check 13: Magisk-owned files / sockets in /dev */
    private fun checkMagiskDevFiles(): DetectionResult {
        // Magisk (all versions) creates various named files/dirs under /dev to hide itself
        // from the regular filesystem. These are detectable by direct path existence checks.
        val devPaths = listOf(
            "/dev/magisk",
            "/dev/magisk_mirror",
            "/dev/magisk_block",
            "/dev/socket/magisk_ptrace",
            "/dev/socket/magiskd",
            "/dev/socket/magisk_loader",
            "/dev/.magisk",
            "/dev/.magisk.unblock",
            "/dev/.su",
            "/dev/socket/su"
        )
        val found = devPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "magisk_dev_files",
                name = "Magisk /dev Files Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Magisk-specific files or sockets found in /dev.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "Magisk uses the /dev filesystem (tmpfs) to create control sockets and " +
                    "mirror points that it can access from any SELinux context. " +
                    "These files only exist on devices with active Magisk.",
                solution = "Uninstall Magisk to remove these /dev artifacts.",
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_dev_files",
                name = "Magisk /dev Files",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Magisk /dev files or sockets found.",
                detailedReason = "No Magisk-specific files were found under /dev.",
                solution = "No action required."
            )
        }
    }

    /** Check 14: Zygisk native library loaded into this process (/proc/self/maps filename check) */
    private fun checkZygiskActiveInMaps(): DetectionResult {
        // Zygisk injects its native library into every app process. The library filename
        // (not the full path) will contain "zygisk" when Magisk+Zygisk is active.
        val zygiskLibPatterns = listOf(
            "libzygisk.so",
            "libzygisk_", // versioned variants
            "zygisk_lsposed.so",
            "zygisk_companion.so"
        )
        return try {
            val maps = File("/proc/self/maps").readText()
            val found = mutableListOf<String>()
            maps.lines().forEach { line ->
                if (!line.contains(".so")) return@forEach
                val path = line.trim().split("\\s+".toRegex()).lastOrNull()?.trim() ?: return@forEach
                val filename = path.substringAfterLast("/").lowercase()
                zygiskLibPatterns.forEach { pat ->
                    if (filename.contains(pat) && !found.contains(path.take(80))) {
                        found.add(path.take(80))
                    }
                }
            }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "zygisk_active_maps",
                    name = "Zygisk Library Injected",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "Zygisk native library is loaded in this process.",
                    detailedReason = "Zygisk library found in /proc/self/maps: ${found.joinToString(", ")}. " +
                        "Zygisk (Zygote + Magisk) injects its native library into every app " +
                        "process by hooking the Zygote process before forks. " +
                        "This confirms Zygisk is actively running.",
                    solution = "Disable Zygisk in Magisk settings or uninstall Magisk.",
                    technicalDetail = "Injected libs: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "zygisk_active_maps",
                    name = "Zygisk Library",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "No Zygisk library found in process memory maps.",
                    detailedReason = "No Zygisk native library was found in /proc/self/maps.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "zygisk_active_maps",
                name = "Zygisk Library",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = "Could not read /proc/self/maps.",
                detailedReason = "Error: ${e.message}",
                solution = "Ensure /proc/self/maps is accessible."
            )
        }
    }

    /** Check 15: Magisk stub APK — Magisk can masquerade as a random app but retains specific metadata */
    private fun checkMagiskStubApp(): DetectionResult {
        // When Magisk Manager is hidden, it's repackaged as a stub APK.
        // The stub always declares a specific set of permissions and an activity name pattern.
        // We detect it by scanning installed packages for Magisk-characteristic permissions/activities.
        val magiskPermissions = setOf(
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.READ_EXTERNAL_STORAGE"
        )
        val knownMagiskPermission = "android.permission.CHANGE_CONFIGURATION"
        val suspiciousPackages = mutableListOf<String>()

        try {
            val pm = context.packageManager
            val flag = PackageManager.GET_PERMISSIONS
            pm.getInstalledPackages(flag).forEach { pkg ->
                val pkgName = pkg.packageName
                // Skip known legitimate apps and Magisk's own known package names
                if (pkgName.startsWith("com.android") || pkgName.startsWith("android") ||
                    pkgName == "com.topjohnwu.magisk" || pkgName == context.packageName
                ) return@forEach

                // A stub Magisk app requests a very specific and unusual combination of permissions
                val declaredPerms = pkg.requestedPermissions?.toSet() ?: return@forEach
                if (magiskPermissions.all { it in declaredPerms } &&
                    knownMagiskPermission in declaredPerms
                ) {
                    // Also check if it has a provider with a Magisk-like authority pattern
                    try {
                        val pkgInfo = pm.getPackageInfo(pkgName, PackageManager.GET_PROVIDERS)
                        val hasMagiskProvider = pkgInfo.providers?.any { p ->
                            p.authority?.contains("magisk", ignoreCase = true) == true ||
                                p.name?.contains("magisk", ignoreCase = true) == true
                        } ?: false
                        if (hasMagiskProvider) suspiciousPackages.add(pkgName)
                    } catch (_: Exception) {}
                }
            }
        } catch (_: Exception) {}

        return if (suspiciousPackages.isNotEmpty()) {
            DetectionResult(
                id = "magisk_stub_app",
                name = "Magisk Stub App Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "App with Magisk stub APK characteristics found.",
                detailedReason = "Package(s) with Magisk stub metadata: ${suspiciousPackages.joinToString(", ")}. " +
                    "Magisk's hide feature repackages itself as an innocent-looking app. " +
                    "The stub retains Magisk's content provider authority and specific permission set.",
                solution = "Open the stub app and uninstall Magisk through it.",
                technicalDetail = "Suspect packages: ${suspiciousPackages.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_stub_app",
                name = "Magisk Stub App",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No Magisk stub app detected.",
                detailedReason = "No installed packages match the Magisk stub APK signature.",
                solution = "No action required."
            )
        }
    }

    /** Check 16: Magisk SELinux context — Magisk sets a custom selinux context for its processes */
    private fun checkMagiskSELinuxContext(): DetectionResult {
        return try {
            // /proc/self/attr/current contains our own SELinux context
            val selfContext = File("/proc/self/attr/current").readText().trim()
            // /proc/self/attr/sockcreate is used for sockets
            val sockContext = runCatching { File("/proc/self/attr/sockcreate").readText().trim() }.getOrDefault("")

            val magiskContexts = listOf("magisk", "su", "superuser", "rootd")
            val foundContexts = mutableListOf<String>()
            if (magiskContexts.any { selfContext.contains(it, ignoreCase = true) }) {
                foundContexts.add("current=$selfContext")
            }
            if (sockContext.isNotEmpty() && magiskContexts.any { sockContext.contains(it, ignoreCase = true) }) {
                foundContexts.add("sockcreate=$sockContext")
            }

            // Also scan other processes' SELinux contexts for magisk
            val procDir = File("/proc")
            procDir.listFiles()?.forEach { pidDir ->
                if (!pidDir.isDirectory || !pidDir.name.all { it.isDigit() }) return@forEach
                try {
                    val ctx = File(pidDir, "attr/current").readText().trim()
                    if (magiskContexts.any { ctx.contains(it, ignoreCase = true) }) {
                        val name = runCatching {
                            File(pidDir, "comm").readText().trim()
                        }.getOrDefault(pidDir.name)
                        if (!foundContexts.any { it.contains(name) }) {
                            foundContexts.add("pid ${pidDir.name}($name)=$ctx")
                        }
                    }
                } catch (_: Exception) {}
            }

            if (foundContexts.isNotEmpty()) {
                DetectionResult(
                    id = "magisk_selinux",
                    name = "Magisk SELinux Context Detected",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "Magisk-related SELinux context found.",
                    detailedReason = "Found: ${foundContexts.take(3).joinToString(", ")}. " +
                        "Magisk injects custom SELinux policy rules and some versions run " +
                        "under their own SELinux context (u:r:magisk:s0). " +
                        "A non-standard SELinux context for a root-related process confirms Magisk activity.",
                    solution = "Remove Magisk to restore standard SELinux policy.",
                    technicalDetail = foundContexts.take(5).joinToString("; ")
                )
            } else {
                DetectionResult(
                    id = "magisk_selinux",
                    name = "Magisk SELinux Context",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "No Magisk SELinux contexts detected.",
                    detailedReason = "No Magisk-related SELinux contexts found in /proc/*/attr/current.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "magisk_selinux",
                name = "Magisk SELinux Context",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not read SELinux contexts.",
                detailedReason = "Error: ${e.message}",
                solution = "Ensure /proc/self/attr/current is accessible."
            )
        }
    }

    /** Check 17: Magisk APEX overlay — Magisk can overlay files inside /apex partitions */
    private fun checkMagiskApexOverlay(): DetectionResult {
        val apexMagiskPaths = listOf(
            "/apex/.magisk",
            "/apex/magisk"
        )
        // Also look for 'orig' directories inside APEX mounts — these are created by Magisk
        // when it bind-mounts over APEX libraries
        val apexOrigPatterns = mutableListOf<String>()
        try {
            val apexDir = File("/apex")
            if (apexDir.exists() && apexDir.isDirectory) {
                apexDir.listFiles()?.forEach { apexChild ->
                    val origDir = File(apexChild, "orig")
                    if (origDir.exists()) apexOrigPatterns.add(origDir.path)
                }
            }
        } catch (_: Exception) {}

        val foundDirect = apexMagiskPaths.filter { File(it).exists() }
        val allFound = foundDirect + apexOrigPatterns

        return if (allFound.isNotEmpty()) {
            DetectionResult(
                id = "magisk_apex",
                name = "Magisk APEX Overlay Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Magisk overlay inside /apex detected.",
                detailedReason = "Found: ${allFound.take(5).joinToString(", ")}. " +
                    "Magisk (v24+) can inject modules into APEX (Android Pony EXpress) " +
                    "partition libraries by bind-mounting over them. " +
                    "The 'orig' directory is created as a backup of the original APEX content. " +
                    "These artefacts are only present when Magisk modules are active.",
                solution = "Disable APEX-targeting modules in Magisk Manager or uninstall Magisk.",
                technicalDetail = "Paths: ${allFound.take(10).joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_apex",
                name = "Magisk APEX Overlay",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No Magisk APEX overlay detected.",
                detailedReason = "No Magisk-specific files were found inside /apex.",
                solution = "No action required."
            )
        }
    }

    /**
     * Check 18: Magisk file descriptors in /proc/self/fd.
     * Magisk keeps open file descriptors to its internal files (mirrors, sockets, binaries).
     * Reading the symlink targets for each fd reveals paths that should not be open in a
     * normal process — magisk/libmagisk/sbin paths are clear indicators.
     */
    private fun checkMagiskFileDescriptors(): DetectionResult {
        val suspiciousFds = mutableListOf<String>()
        try {
            val fdDir = File("/proc/self/fd")
            val fds = fdDir.listFiles() ?: emptyArray()
            for (fd in fds) {
                try {
                    val link = fd.canonicalPath
                    if (link.contains("magisk", ignoreCase = true) ||
                        link.contains("libmagisk", ignoreCase = true) ||
                        link.contains("/dev/magisk", ignoreCase = true) ||
                        link.contains("/sbin/.magisk", ignoreCase = true)
                    ) {
                        suspiciousFds.add(link.take(60))
                    }
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}

        return if (suspiciousFds.isNotEmpty()) {
            DetectionResult(
                id = "magisk_fd",
                name = "Magisk File Descriptors Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "This process has open file descriptors pointing to Magisk paths.",
                detailedReason = "Found in /proc/self/fd: ${suspiciousFds.take(5).joinToString(", ")}. " +
                    "Magisk keeps open FDs to its mirror mount points and socket files. " +
                    "The presence of these FDs in an app process confirms Magisk has touched this process.",
                solution = "Remove Magisk to clear these file descriptor references.",
                technicalDetail = "FD targets: ${suspiciousFds.take(8).joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_fd",
                name = "Magisk File Descriptors",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Magisk-related file descriptors found in /proc/self/fd.",
                detailedReason = "No open file descriptors point to Magisk paths.",
                solution = "No action required."
            )
        }
    }

    /**
     * Check 19: Native bridge injection (ro.dalvik.vm.native.bridge).
     * Riru (Magisk module) injects itself by replacing the native bridge library.
     * This property normally contains "0" or is absent on stock devices.
     * A non-standard value (especially libriru*.so or libzygisk_loader.so) indicates Riru/Zygisk.
     */
    private fun checkNativeBridgeInjection(): DetectionResult {
        val suspiciousBridges = listOf(
            "libriru", "libzygisk_loader", "libnb", "libhoudini64",
            "libhoudini", "libriruloader"
        )
        val bridgeValue = getSystemProperty("ro.dalvik.vm.native.bridge").trim()
        val emptyOrStock = bridgeValue.isEmpty() || bridgeValue == "0"
        val isSuspicious = !emptyOrStock &&
            suspiciousBridges.any { bridgeValue.contains(it, ignoreCase = true) }

        // Also check via SystemProperties reflection (more reliable)
        val reflectedValue = runCatching {
            val sp = Class.forName("android.os.SystemProperties")
            sp.getMethod("get", String::class.java, String::class.java)
                .invoke(null, "ro.dalvik.vm.native.bridge", "") as String
        }.getOrDefault(bridgeValue)
        val isSuspiciousReflected = reflectedValue.isNotEmpty() &&
            reflectedValue != "0" &&
            suspiciousBridges.any { reflectedValue.contains(it, ignoreCase = true) }

        val detected = isSuspicious || isSuspiciousReflected
        val actualValue = if (reflectedValue.isNotEmpty()) reflectedValue else bridgeValue

        return if (detected) {
            DetectionResult(
                id = "native_bridge",
                name = "Native Bridge Injection Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Riru/Zygisk native bridge injection detected.",
                detailedReason = "ro.dalvik.vm.native.bridge = '$actualValue'. " +
                    "Riru (a predecessor of Zygisk) hijacks the ART native bridge mechanism " +
                    "by replacing this property with its own loader library. " +
                    "A suspicious value here is a strong indicator of Riru/Zygisk-based injection.",
                solution = "Remove the Riru or Zygisk Magisk module to restore the normal native bridge.",
                technicalDetail = "ro.dalvik.vm.native.bridge=$actualValue"
            )
        } else {
            DetectionResult(
                id = "native_bridge",
                name = "Native Bridge",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No suspicious native bridge injection found.",
                detailedReason = "ro.dalvik.vm.native.bridge is '$actualValue' — stock value.",
                solution = "No action required."
            )
        }
    }

    /**
     * Check 20: ZygiskSU / Zygisk Next daemon processes.
     * Zygisk Next (formerly ZygiskSU) runs companion daemon processes with characteristic names.
     * These can be detected by scanning /proc/[pid]/cmdline for their process names.
     */
    private fun checkZygiskSUDaemon(): DetectionResult {
        val daemonPatterns = listOf(
            "zn-daemon",            // ZygiskSU main daemon
            "zn-nsdaemon",          // ZygiskSU namespace daemon
            "zn-zygisk-companion",  // ZygiskSU Zygisk companion
            "zygisk_gadget",        // Frida gadget via Zygisk
            "rezygisk",             // ReZygisk
            "zygisk-ptrace",        // Zygisk ptrace helper
            "magiskd",              // Magisk daemon
            "magisk_loader"         // Magisk loader process
        )
        val foundDaemons = mutableListOf<String>()

        try {
            File("/proc").listFiles()?.forEach { pidDir ->
                if (!pidDir.isDirectory || !pidDir.name.all { it.isDigit() }) return@forEach
                try {
                    val cmdline = File(pidDir, "cmdline").readText()
                        .replace('\u0000', ' ').trim()
                    daemonPatterns.forEach { pattern ->
                        if (cmdline.contains(pattern, ignoreCase = true) &&
                            !foundDaemons.contains(pattern)
                        ) {
                            foundDaemons.add(pattern)
                        }
                    }
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}

        return if (foundDaemons.isNotEmpty()) {
            DetectionResult(
                id = "zygisk_su_daemon",
                name = "Zygisk Companion Daemon Detected",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Zygisk/Magisk daemon processes are running.",
                detailedReason = "Found daemon process(es): ${foundDaemons.joinToString(", ")}. " +
                    "Zygisk Next (a standalone Zygisk implementation) runs privileged daemon processes " +
                    "named zn-daemon, zn-nsdaemon, and zn-zygisk-companion. " +
                    "Magisk itself runs as 'magiskd'. These are definitive indicators of active root injection.",
                solution = "Uninstall Magisk or the Zygisk Next module to remove these daemon processes.",
                technicalDetail = "Daemons: ${foundDaemons.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "zygisk_su_daemon",
                name = "Zygisk/Magisk Daemon Processes",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Zygisk/Magisk daemon processes found.",
                detailedReason = "No Zygisk Next or Magisk daemon process names were found in /proc/*/cmdline.",
                solution = "No action required."
            )
        }
    }

    /**
     * Check 21: Timing-based detection.
     * Magisk hooks the `access(2)` and `stat(2)` syscalls (via DenyList) to hide files.
     * Hooked calls take significantly longer than direct syscalls.
     * We measure latency of File.exists() on a known Magisk path and compare with a baseline.
     */
    private fun checkMagiskTimingLatency(): DetectionResult {
        return try {
            val magiskPath = "/data/adb/magisk"
            val baselinePath = "/data/adb/nonexistent_baseline_9283"
            val iterations = 5

            // Warm up JIT
            repeat(2) {
                File(magiskPath).exists()
                File(baselinePath).exists()
            }

            // Measure baseline (nonexistent path, no hook)
            val baselineStart = System.nanoTime()
            repeat(iterations) { File(baselinePath).exists() }
            val baselineNs = (System.nanoTime() - baselineStart) / iterations

            // Measure Magisk path
            val magiskStart = System.nanoTime()
            repeat(iterations) { File(magiskPath).exists() }
            val magiskNs = (System.nanoTime() - magiskStart) / iterations

            // If Magisk DenyList hooks stat(), the Magisk path access is much slower
            // Threshold: >4× slower than baseline AND >3ms absolute
            val ratio = if (baselineNs > 0) magiskNs.toDouble() / baselineNs else 0.0
            val absoluteMs = magiskNs / 1_000_000.0
            val detected = ratio > 4.0 && absoluteMs > 3.0

            if (detected) {
                DetectionResult(
                    id = "magisk_timing",
                    name = "Magisk Hook Latency Anomaly",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = "Suspicious file access latency suggests Magisk DenyList hooks.",
                    detailedReason = "File.exists('$magiskPath') took ${String.format("%.2f", absoluteMs)}ms " +
                        "(${String.format("%.1f", ratio)}× slower than baseline). " +
                        "Magisk's DenyList patches intercept filesystem calls to hide Magisk files. " +
                        "This interception adds measurable latency compared to accessing non-hooked paths.",
                    solution = "Disable Magisk DenyList or uninstall Magisk.",
                    technicalDetail = "magisk=${magiskNs}ns baseline=${baselineNs}ns ratio=${String.format("%.2f", ratio)}"
                )
            } else {
                DetectionResult(
                    id = "magisk_timing",
                    name = "File Access Timing",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = "No suspicious timing anomaly for Magisk file access.",
                    detailedReason = "File.exists() latency is within normal range " +
                        "(ratio=${String.format("%.1f", ratio)}×, ${String.format("%.2f", absoluteMs)}ms). " +
                        "No Magisk DenyList hook latency detected.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "magisk_timing",
                name = "File Access Timing",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.MEDIUM,
                description = "Timing check failed.",
                detailedReason = "Error: ${e.message}",
                solution = "No action required."
            )
        }
    }

    /**
     * Check 22: Broader /proc/self/maps scan for root-framework libraries.
     * While checkZygiskActiveInMaps looks for Zygisk-specific filenames,
     * this check casts a wider net: libsu.so, libriru*, libmagisk*, libxposed*, libwhale, libdobby,
     * libsandhook, libpine, etc. These are native hook engines used by multiple frameworks.
     */
    private fun checkBroaderMapsPatterns(): DetectionResult {
        val suspiciousLibPatterns = listOf(
            "libsu.so",           // libsu (Magisk's root access library)
            "libriru",            // Riru framework library
            "libmagisk",          // Magisk native library
            "libwhale",           // Whale hook framework (used by Xposed forks)
            "libdobby",           // Dobby inline hook framework
            "libsandhook",        // SandHook ART hook engine
            "libpine",            // Pine ART hook framework
            "libepic",            // Epic ART hook framework
            "dreamland",          // Dreamland Xposed fork
            "libhook",            // Generic hook library
            "zygote-loader"       // Zygote loader variant
        )
        val found = mutableListOf<String>()
        try {
            val maps = File("/proc/self/maps").readText()
            maps.lines().forEach { line ->
                val path = line.trim().split("\\s+".toRegex()).lastOrNull()?.trim() ?: return@forEach
                if (path.isEmpty() || path.startsWith("[") || !path.contains("/")) return@forEach
                val filename = path.substringAfterLast("/").lowercase()
                suspiciousLibPatterns.forEach { pat ->
                    if (filename.contains(pat) && !found.any { it.contains(pat) }) {
                        found.add("$pat → ${path.take(70)}")
                    }
                }
            }
        } catch (_: Exception) {}

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "broad_maps",
                name = "Root/Hook Libraries in Process Memory",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Root or hook framework native libraries are loaded in this process.",
                detailedReason = "Found in /proc/self/maps: ${found.take(5).joinToString(", ")}. " +
                    "These are native libraries belonging to Magisk (libsu), Riru, and inline hook engines " +
                    "(Dobby, SandHook, Pine, Whale) used by Xposed-compatible frameworks. " +
                    "Their presence confirms active injection into this process.",
                solution = "Remove the relevant root framework or module to prevent library injection.",
                technicalDetail = found.take(10).joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "broad_maps",
                name = "Root/Hook Libraries",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No root/hook framework native libraries found in process memory.",
                detailedReason = "No known root/hook library names were found in /proc/self/maps.",
                solution = "No action required."
            )
        }
    }

    // ---- Utilities ----

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
