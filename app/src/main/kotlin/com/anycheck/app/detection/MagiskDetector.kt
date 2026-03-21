package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.anycheck.app.R
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
                name = context.getString(R.string.chk_magisk_files_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_files_desc),
                detailedReason = context.getString(R.string.chk_magisk_files_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_magisk_files_solution),
                technicalDetail = "Files found: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_files",
                name = context.getString(R.string.chk_magisk_files_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_files_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_files_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_magisk_dirs_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_dirs_desc),
                detailedReason = context.getString(R.string.chk_magisk_dirs_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_magisk_dirs_solution),
                technicalDetail = "Directories found: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_dirs",
                name = context.getString(R.string.chk_magisk_dirs_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_dirs_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_dirs_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_magisk_db_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_db_desc),
                detailedReason = context.getString(R.string.chk_magisk_db_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_magisk_db_solution),
                technicalDetail = "DB paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_db",
                name = context.getString(R.string.chk_magisk_db_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_db_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_db_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_magisk_packages_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_packages_desc),
                detailedReason = context.getString(R.string.chk_magisk_packages_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_magisk_packages_solution),
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_packages",
                name = context.getString(R.string.chk_magisk_packages_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_packages_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_packages_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_magisk_su_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_su_desc),
                detailedReason = context.getString(R.string.chk_magisk_su_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_magisk_su_solution),
                technicalDetail = "Binaries: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_su",
                name = context.getString(R.string.chk_magisk_su_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_su_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_su_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                    name = context.getString(R.string.chk_magisk_unix_socket_name),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_magisk_unix_socket_desc),
                    detailedReason = context.getString(R.string.chk_magisk_unix_socket_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_magisk_unix_socket_solution),
                    technicalDetail = "Socket names found: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "magisk_unix_socket",
                    name = context.getString(R.string.chk_magisk_unix_socket_name_nd),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_magisk_unix_socket_desc_nd),
                    detailedReason = context.getString(R.string.chk_magisk_unix_socket_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "magisk_unix_socket",
                name = context.getString(R.string.chk_magisk_unix_socket_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_unix_socket_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_unix_socket_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
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
                    name = context.getString(R.string.chk_magisk_mounts_name),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_magisk_mounts_desc),
                    detailedReason = context.getString(R.string.chk_magisk_mounts_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_magisk_mounts_solution),
                    technicalDetail = "Keywords: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "magisk_mounts",
                    name = context.getString(R.string.chk_magisk_mounts_name_nd),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_magisk_mounts_desc_nd),
                    detailedReason = context.getString(R.string.chk_magisk_mounts_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "magisk_mounts",
                name = context.getString(R.string.chk_magisk_mounts_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_mounts_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_mounts_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_magisk_props_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_magisk_props_desc),
                detailedReason = context.getString(R.string.chk_magisk_props_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_magisk_props_solution),
                technicalDetail = "Props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_props",
                name = context.getString(R.string.chk_magisk_props_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_magisk_props_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_props_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_zygisk_lib_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_zygisk_lib_desc),
                detailedReason = context.getString(R.string.chk_zygisk_lib_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_zygisk_lib_solution),
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "zygisk_lib",
                name = context.getString(R.string.chk_zygisk_lib_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_zygisk_lib_desc_nd),
                detailedReason = context.getString(R.string.chk_zygisk_lib_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_magisk_hide_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_hide_desc),
                detailedReason = context.getString(R.string.chk_magisk_hide_reason, reasons.joinToString("; ")),
                solution = context.getString(R.string.chk_magisk_hide_solution),
                technicalDetail = "Indicators: ${reasons.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_hide",
                name = context.getString(R.string.chk_magisk_hide_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_hide_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_hide_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                    name = context.getString(R.string.chk_magisk_processes_name),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_magisk_processes_desc),
                    detailedReason = context.getString(R.string.chk_magisk_processes_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_magisk_processes_solution),
                    technicalDetail = "Processes: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "magisk_processes",
                    name = context.getString(R.string.chk_magisk_processes_name_nd),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_magisk_processes_desc_nd),
                    detailedReason = context.getString(R.string.chk_magisk_processes_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "magisk_processes",
                name = context.getString(R.string.chk_magisk_processes_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_processes_desc_error),
                detailedReason = context.getString(R.string.chk_magisk_processes_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_magisk_hidden_manager_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_magisk_hidden_manager_desc_error),
                detailedReason = context.getString(R.string.chk_magisk_hidden_manager_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }

        return if (hiddenIndicators.isNotEmpty()) {
            DetectionResult(
                id = "magisk_hidden_manager",
                name = context.getString(R.string.chk_magisk_hidden_manager_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_magisk_hidden_manager_desc),
                detailedReason = context.getString(R.string.chk_magisk_hidden_manager_reason, hiddenIndicators.joinToString(", ")),
                solution = context.getString(R.string.chk_magisk_hidden_manager_solution),
                technicalDetail = "Indicators: ${hiddenIndicators.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_hidden_manager",
                name = context.getString(R.string.chk_magisk_hidden_manager_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_magisk_hidden_manager_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_hidden_manager_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_magisk_dev_files_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_dev_files_desc),
                detailedReason = context.getString(R.string.chk_magisk_dev_files_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_magisk_dev_files_solution),
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_dev_files",
                name = context.getString(R.string.chk_magisk_dev_files_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_dev_files_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_dev_files_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                    name = context.getString(R.string.chk_zygisk_active_maps_name),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_zygisk_active_maps_desc),
                    detailedReason = context.getString(R.string.chk_zygisk_active_maps_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_zygisk_active_maps_solution),
                    technicalDetail = "Injected libs: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "zygisk_active_maps",
                    name = context.getString(R.string.chk_zygisk_active_maps_name_nd),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_zygisk_active_maps_desc_nd),
                    detailedReason = context.getString(R.string.chk_zygisk_active_maps_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "zygisk_active_maps",
                name = context.getString(R.string.chk_zygisk_active_maps_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_zygisk_active_maps_desc_error),
                detailedReason = context.getString(R.string.chk_zygisk_active_maps_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_magisk_stub_app_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_stub_app_desc),
                detailedReason = context.getString(R.string.chk_magisk_stub_app_reason, suspiciousPackages.joinToString(", ")),
                solution = context.getString(R.string.chk_magisk_stub_app_solution),
                technicalDetail = "Suspect packages: ${suspiciousPackages.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_stub_app",
                name = context.getString(R.string.chk_magisk_stub_app_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_stub_app_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_stub_app_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                    name = context.getString(R.string.chk_magisk_selinux_name),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_magisk_selinux_desc),
                    detailedReason = context.getString(R.string.chk_magisk_selinux_reason, foundContexts.take(3).joinToString(", ")),
                    solution = context.getString(R.string.chk_magisk_selinux_solution),
                    technicalDetail = foundContexts.take(5).joinToString("; ")
                )
            } else {
                DetectionResult(
                    id = "magisk_selinux",
                    name = context.getString(R.string.chk_magisk_selinux_name_nd),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_magisk_selinux_desc_nd),
                    detailedReason = context.getString(R.string.chk_magisk_selinux_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "magisk_selinux",
                name = context.getString(R.string.chk_magisk_selinux_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_selinux_desc_error),
                detailedReason = context.getString(R.string.chk_magisk_selinux_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_magisk_apex_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_apex_desc),
                detailedReason = context.getString(R.string.chk_magisk_apex_reason, allFound.take(5).joinToString(", ")),
                solution = context.getString(R.string.chk_magisk_apex_solution),
                technicalDetail = "Paths: ${allFound.take(10).joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_apex",
                name = context.getString(R.string.chk_magisk_apex_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_magisk_apex_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_apex_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_magisk_fd_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_fd_desc),
                detailedReason = context.getString(R.string.chk_magisk_fd_reason, suspiciousFds.take(5).joinToString(", ")),
                solution = context.getString(R.string.chk_magisk_fd_solution),
                technicalDetail = "FD targets: ${suspiciousFds.take(8).joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "magisk_fd",
                name = context.getString(R.string.chk_magisk_fd_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_magisk_fd_desc_nd),
                detailedReason = context.getString(R.string.chk_magisk_fd_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_native_bridge_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_native_bridge_desc),
                detailedReason = context.getString(R.string.chk_native_bridge_reason, actualValue),
                solution = context.getString(R.string.chk_native_bridge_solution),
                technicalDetail = "ro.dalvik.vm.native.bridge=$actualValue"
            )
        } else {
            DetectionResult(
                id = "native_bridge",
                name = context.getString(R.string.chk_native_bridge_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_native_bridge_desc_nd),
                detailedReason = context.getString(R.string.chk_native_bridge_reason_nd, actualValue),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_zygisk_su_daemon_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_zygisk_su_daemon_desc),
                detailedReason = context.getString(R.string.chk_zygisk_su_daemon_reason, foundDaemons.joinToString(", ")),
                solution = context.getString(R.string.chk_zygisk_su_daemon_solution),
                technicalDetail = "Daemons: ${foundDaemons.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "zygisk_su_daemon",
                name = context.getString(R.string.chk_zygisk_su_daemon_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_zygisk_su_daemon_desc_nd),
                detailedReason = context.getString(R.string.chk_zygisk_su_daemon_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                    name = context.getString(R.string.chk_magisk_timing_name),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_magisk_timing_desc),
                    detailedReason = context.getString(
                        R.string.chk_magisk_timing_reason,
                        magiskPath,
                        String.format("%.2f", absoluteMs),
                        String.format("%.1f", ratio)
                    ),
                    solution = context.getString(R.string.chk_magisk_timing_solution),
                    technicalDetail = "magisk=${magiskNs}ns baseline=${baselineNs}ns ratio=${String.format("%.2f", ratio)}"
                )
            } else {
                DetectionResult(
                    id = "magisk_timing",
                    name = context.getString(R.string.chk_magisk_timing_name_nd),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_magisk_timing_desc_nd),
                    detailedReason = context.getString(
                        R.string.chk_magisk_timing_reason_nd,
                        String.format("%.1f", ratio),
                        String.format("%.2f", absoluteMs)
                    ),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "magisk_timing",
                name = context.getString(R.string.chk_magisk_timing_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_magisk_timing_desc_error),
                detailedReason = context.getString(R.string.chk_magisk_timing_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_broad_maps_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_broad_maps_desc),
                detailedReason = context.getString(R.string.chk_broad_maps_reason, found.take(5).joinToString(", ")),
                solution = context.getString(R.string.chk_broad_maps_solution),
                technicalDetail = found.take(10).joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "broad_maps",
                name = context.getString(R.string.chk_broad_maps_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_broad_maps_desc_nd),
                detailedReason = context.getString(R.string.chk_broad_maps_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
