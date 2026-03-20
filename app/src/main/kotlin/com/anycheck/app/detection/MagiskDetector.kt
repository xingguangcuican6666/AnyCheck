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
        checkMagiskManagerHidden()
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
