package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.anycheck.app.R
import android.provider.Settings
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

/**
 * Extra root/security detection checks gathered from GitHub security research repos
 * (rootbeer, android-root-detection, promon, anti-emulator, frida-detection, etc.).
 *
 * Covers: LD_PRELOAD injection, Linux capabilities, overlay/bind-mounts, suid su,
 * BusyBox, terminal & hacking apps, test-keys builds, OEM unlock, mock locations,
 * ADB-over-WiFi, Shamiko, hidden /system mounts, uid=0 processes, security patch age.
 */
class ExtraRootDetector(private val context: Context) {

    companion object {
        // Android 10+ (APEX) always has many overlayfs mounts; fewer than this
        // threshold is a signal that SUSFS or a similar tool is hiding them.
        private const val MIN_EXPECTED_OVERLAY_COUNT = 5
    }

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkLDPreloadEnvironment(),
        checkProcessCapabilities(),
        checkMountInfoOverlay(),
        checkTmpfsMountAtSbin(),
        checkPrivilegedProcesses(),
        checkTerminalAndHackingApps(),
        checkSecurityPatchAge(),
        checkTestKeysBuild(),
        checkOemUnlockAllowed(),
        checkMockLocationsEnabled(),
        checkWirelessAdb(),
        checkBusyBoxInstalled(),
        checkSuBinarySuid(),
        checkShamikoZygiskAssist(),
        checkHiddenSystemBindMounts(),
        checkDataLocalTmpAnomalies(),
        checkSuspiciousToolFiles(),
        checkDebugRamdiskMount(),
        checkMtManagerFiles(),
        checkKernelDirtySuffix(),
        checkDex2oatAnomaly(),
        checkScenePortOccupied(),
        checkHiddenProcessGroups(),
        checkNetlinkSocketAnomaly(),
        checkAuditLogProcesses()
    )

    // ----------------------------------------------------------------
    // Check 1: LD_PRELOAD / LD_LIBRARY_PATH set in this process env
    // ----------------------------------------------------------------
    private fun checkLDPreloadEnvironment(): DetectionResult {
        return try {
            val environ = File("/proc/self/environ").readBytes()
                .toString(Charsets.ISO_8859_1)
                .split("\u0000")
            val ldPreload = environ.firstOrNull { it.startsWith("LD_PRELOAD=") }
            // Flag LD_LIBRARY_PATH only when it includes non-standard (non-system) directories
            val ldLibPath = environ.firstOrNull { e ->
                if (!e.startsWith("LD_LIBRARY_PATH=")) return@firstOrNull false
                val value = e.removePrefix("LD_LIBRARY_PATH=")
                value.split(":").any { dir ->
                    dir.isNotEmpty() &&
                        !dir.startsWith("/system") &&
                        !dir.startsWith("/vendor") &&
                        !dir.startsWith("/apex") &&
                        !dir.startsWith("/product")
                }
            }
            val suspicious = listOfNotNull(ldPreload, ldLibPath)
            if (suspicious.isNotEmpty()) {
                DetectionResult(
                    id = "ld_preload",
                    name = context.getString(R.string.chk_ext_ldpreload_name),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_ext_ldpreload_desc),
                    detailedReason = context.getString(R.string.chk_ext_ldpreload_reason, suspicious.joinToString(", ")),
                    solution = context.getString(R.string.chk_ext_ldpreload_solution),
                    technicalDetail = suspicious.joinToString("; ")
                )
            } else {
                DetectionResult(
                    id = "ld_preload",
                    name = context.getString(R.string.chk_ext_ldpreload_name_nd),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_ext_ldpreload_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_ldpreload_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "ld_preload",
                name = context.getString(R.string.chk_ext_ldpreload_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ext_ldpreload_desc_error),
                detailedReason = context.getString(R.string.err_detail_failed_read, "/proc/self/environ", e.message ?: ""),
                solution = context.getString(R.string.chk_ext_ldpreload_solution_error)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 2: Linux capabilities in /proc/self/status (CapPrm / CapEff)
    // ----------------------------------------------------------------
    private fun checkProcessCapabilities(): DetectionResult {
        return try {
            val status = File("/proc/self/status").readText()
            var capEff = ""
            var capPrm = ""
            status.lines().forEach { line ->
                when {
                    line.startsWith("CapEff:") -> capEff = line.substringAfter(":").trim()
                    line.startsWith("CapPrm:") -> capPrm = line.substringAfter(":").trim()
                }
            }
            // Full capability set for root is ffffffffffffffff
            val effValue = capEff.toLongOrNull(16) ?: 0L
            val prmValue = capPrm.toLongOrNull(16) ?: 0L
            // Non-zero permitted or effective caps beyond normal app baseline indicate elevated privilege
            // Normal apps have 0 effective capabilities
            val elevated = effValue != 0L || prmValue != 0L
            if (elevated) {
                DetectionResult(
                    id = "capabilities",
                    name = context.getString(R.string.chk_ext_caps_name),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_caps_desc),
                    detailedReason = context.getString(R.string.chk_ext_caps_reason, capPrm, capEff),
                    solution = context.getString(R.string.chk_ext_caps_solution),
                    technicalDetail = "CapPrm=$capPrm CapEff=$capEff"
                )
            } else {
                DetectionResult(
                    id = "capabilities",
                    name = context.getString(R.string.chk_ext_caps_name_nd),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_caps_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_caps_reason_nd),
                    solution = context.getString(R.string.no_action_required),
                    technicalDetail = "CapPrm=$capPrm CapEff=$capEff"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "capabilities",
                name = context.getString(R.string.chk_ext_caps_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_caps_desc_error),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.chk_ext_caps_solution_error)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 3: Magisk/KSU overlay mounts in /proc/self/mountinfo
    // Only flags mount entries that reference unambiguously root-framework
    // paths (e.g. /data/adb/magisk, /data/adb/ksu). Vendor and OEM
    // overlayfs mounts that are part of the normal Android system (e.g.
    // those without /data/adb in their source path) are excluded to
    // prevent false positives on stock devices with system-level overlays.
    // ----------------------------------------------------------------
    private fun checkMountInfoOverlay(): DetectionResult {
        return try {
            val mountinfo = File("/proc/self/mountinfo").readText()
            // Count all overlayfs-type mount entries visible to this process.
            // Android 10+ (APEX) and a KSU device without mount-hiding normally
            // show many overlay mounts. Fewer than MIN_EXPECTED_OVERLAY_COUNT means
            // SUSFS (or another mount-hiding mechanism) is suppressing entries —
            // which is itself a strong indicator that a root framework is active
            // and hiding.
            val overlayCount = mountinfo.lines().count { line ->
                val sepIdx = line.indexOf(" - ")
                if (sepIdx < 0) return@count false
                val fsType = line.substring(sepIdx + 3).trim().split(" ").getOrNull(0) ?: ""
                fsType == "overlay" || fsType == "overlayfs"
            }
            if (overlayCount < MIN_EXPECTED_OVERLAY_COUNT) {
                DetectionResult(
                    id = "mountinfo_overlay",
                    name = context.getString(R.string.chk_ext_overlay_name),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_ext_overlay_desc),
                    detailedReason = context.getString(R.string.chk_ext_overlay_reason, overlayCount),
                    solution = context.getString(R.string.chk_ext_overlay_solution),
                    technicalDetail = "overlay mount count: $overlayCount (expected ≥5)"
                )
            } else {
                DetectionResult(
                    id = "mountinfo_overlay",
                    name = context.getString(R.string.chk_ext_overlay_name_nd),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_ext_overlay_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_overlay_reason_nd, overlayCount),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "mountinfo_overlay",
                name = context.getString(R.string.chk_ext_overlay_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ext_overlay_desc_error),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.chk_ext_overlay_solution_error)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 4: tmpfs mounted at /sbin (legacy Magisk pre-v24)
    // ----------------------------------------------------------------
    private fun checkTmpfsMountAtSbin(): DetectionResult {
        return try {
            val mounts = File("/proc/mounts").readText()
            val sbinTmpfs = mounts.lines().any { line ->
                val parts = line.split(" ")
                parts.size >= 3 && parts[1] == "/sbin" && parts[2] == "tmpfs"
            }
            if (sbinTmpfs) {
                DetectionResult(
                    id = "sbin_tmpfs",
                    name = context.getString(R.string.chk_ext_sbin_tmpfs_name),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_sbin_tmpfs_desc),
                    detailedReason = context.getString(R.string.chk_ext_sbin_tmpfs_reason),
                    solution = context.getString(R.string.chk_ext_sbin_tmpfs_solution),
                    technicalDetail = "/sbin mounted as tmpfs"
                )
            } else {
                DetectionResult(
                    id = "sbin_tmpfs",
                    name = context.getString(R.string.chk_ext_sbin_tmpfs_name_nd),
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_sbin_tmpfs_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_sbin_tmpfs_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "sbin_tmpfs",
                name = context.getString(R.string.chk_ext_sbin_tmpfs_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_sbin_tmpfs_desc_error),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.chk_ext_sbin_tmpfs_solution_error)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 5: uid=0 non-kernel processes in /proc
    // ----------------------------------------------------------------
    private fun checkPrivilegedProcesses(): DetectionResult {
        val expectedRootProcesses = setOf(
            "kthreadd", "kworker", "ksoftirqd", "migration", "rcu_", "watchdog",
            "kdevtmpfs", "init", "zygote", "zygote64", "surfaceflinger",
            "servicemanager", "vold", "netd", "drmserver", "mediaserver",
            "installd", "keystore", "logd", "ueventd", "lmkd",
            "adbd", "audioserver", "cameraserver", "tombstoned"
        )
        val suspiciousRootProcs = mutableListOf<String>()
        return try {
            val procDir = File("/proc")
            procDir.listFiles()?.forEach { pidDir ->
                if (!pidDir.isDirectory || !pidDir.name.all { it.isDigit() }) return@forEach
                try {
                    val statusFile = File(pidDir, "status")
                    var name = ""
                    var uid = -1
                    statusFile.readLines().forEach { line ->
                        if (line.startsWith("Name:")) name = line.substringAfter(":").trim()
                        if (line.startsWith("Uid:")) {
                            uid = line.substringAfter(":").trim().split("\\s+".toRegex())
                                .firstOrNull()?.toIntOrNull() ?: -1
                        }
                    }
                    if (uid == 0 && name.isNotEmpty()) {
                        val isExpected = expectedRootProcesses.any { expected ->
                            name.startsWith(expected, ignoreCase = true)
                        }
                        if (!isExpected && !suspiciousRootProcs.contains(name)) {
                            suspiciousRootProcs.add(name)
                        }
                    }
                } catch (_: Exception) {}
            }
            if (suspiciousRootProcs.isNotEmpty()) {
                DetectionResult(
                    id = "privileged_processes",
                    name = context.getString(R.string.chk_ext_priv_proc_name),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_priv_proc_desc),
                    detailedReason = context.getString(R.string.chk_ext_priv_proc_reason, suspiciousRootProcs.size, suspiciousRootProcs.take(10).joinToString(", ")),
                    solution = context.getString(R.string.chk_ext_priv_proc_solution),
                    technicalDetail = "Root processes: ${suspiciousRootProcs.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "privileged_processes",
                    name = context.getString(R.string.chk_ext_priv_proc_name_nd),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_priv_proc_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_priv_proc_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "privileged_processes",
                name = context.getString(R.string.chk_ext_priv_proc_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_priv_proc_desc_error),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.chk_ext_priv_proc_solution_error)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 6: Terminal emulator and hacking tool apps
    // ----------------------------------------------------------------
    private fun checkTerminalAndHackingApps(): DetectionResult {
        val dangerousApps = mapOf(
            "com.termux" to "Termux (full Linux terminal/package manager)",
            "com.termux.api" to "Termux API",
            "com.termux.boot" to "Termux:Boot",
            "jackpal.androidterm" to "Android Terminal Emulator",
            "org.connectbot" to "ConnectBot (SSH client)",
            "com.juicessh" to "JuiceSSH",
            "com.googlecode.android_scripting" to "SL4A (Android Scripting)",
            "com.fx.dalvik" to "FX Dalvik explorer",
            "com.offsec.nethunter" to "Kali NetHunter",
            "com.offsec.nethunter.store" to "NetHunter Store",
            "com.offsec.nhsystem" to "NetHunter System",
            "com.simplemobiletools.filemanager.pro" to "Root File Manager",
            "com.estrongs.android.pop" to "ES File Explorer (legacy root access)",
            "com.jrummy.root.browserfree" to "Root Browser",
            "com.jrummy.apps.root.access" to "Root Access",
            "stericson.busybox" to "BusyBox Installer",
            "com.crossbowffs.remotepreferences" to "RemotePreferences (root IPC)",
            "com.sds.android.ttpod" to "DriveDroid (boot ISO via USB)",
            "com.keramidas.TitaniumBackup" to "Titanium Backup (requires root)"
        )
        val found = dangerousApps.filter { packageExists(it.key) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "terminal_hacking_apps",
                name = context.getString(R.string.chk_ext_hacking_apps_name),
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_hacking_apps_desc),
                detailedReason = context.getString(R.string.chk_ext_hacking_apps_reason, found.size, found.values.joinToString(", ")),
                solution = context.getString(R.string.chk_ext_hacking_apps_solution),
                technicalDetail = found.keys.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "terminal_hacking_apps",
                name = context.getString(R.string.chk_ext_hacking_apps_name_nd),
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_hacking_apps_desc_nd),
                detailedReason = context.getString(R.string.chk_ext_hacking_apps_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 7: Android security patch level age (> 1 year = concerning)
    // ----------------------------------------------------------------
    private fun checkSecurityPatchAge(): DetectionResult {
        return try {
            val patchStr = Build.VERSION.SECURITY_PATCH // Format: "YYYY-MM-DD"
            val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
            val patchDate = LocalDate.parse(patchStr, formatter)
            val today = LocalDate.now()
            val monthsOld = ChronoUnit.MONTHS.between(patchDate, today)

            when {
                monthsOld >= 24 -> DetectionResult(
                    id = "security_patch_age",
                    name = context.getString(R.string.chk_ext_sec_patch_name_critical),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_sec_patch_desc_critical, monthsOld),
                    detailedReason = context.getString(R.string.chk_ext_sec_patch_reason_critical, patchStr, monthsOld),
                    solution = context.getString(R.string.chk_ext_sec_patch_solution_critical),
                    technicalDetail = "SECURITY_PATCH=$patchStr monthsOld=$monthsOld"
                )
                monthsOld >= 12 -> DetectionResult(
                    id = "security_patch_age",
                    name = context.getString(R.string.chk_ext_sec_patch_name_warn),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_sec_patch_desc_warn, monthsOld),
                    detailedReason = context.getString(R.string.chk_ext_sec_patch_reason_warn, patchStr, monthsOld),
                    solution = context.getString(R.string.chk_ext_sec_patch_solution_warn),
                    technicalDetail = "SECURITY_PATCH=$patchStr monthsOld=$monthsOld"
                )
                else -> DetectionResult(
                    id = "security_patch_age",
                    name = context.getString(R.string.chk_ext_sec_patch_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_sec_patch_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_sec_patch_reason_nd, patchStr, monthsOld),
                    solution = context.getString(R.string.no_action_required),
                    technicalDetail = "SECURITY_PATCH=$patchStr monthsOld=$monthsOld"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "security_patch_age",
                name = context.getString(R.string.chk_ext_sec_patch_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_sec_patch_desc_error),
                detailedReason = context.getString(R.string.err_detail_error, e.message ?: ""),
                solution = context.getString(R.string.chk_ext_sec_patch_solution_error)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 8: ro.build.tags = "test-keys" (unsigned / AOSP debug build)
    // ----------------------------------------------------------------
    private fun checkTestKeysBuild(): DetectionResult {
        val buildTags = getSystemProperty("ro.build.tags")
        val isTestKeys = buildTags.contains("test-keys", ignoreCase = true)
        return if (isTestKeys) {
            DetectionResult(
                id = "extra_test_keys",
                name = context.getString(R.string.chk_ext_test_keys_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_test_keys_desc),
                detailedReason = context.getString(R.string.chk_ext_test_keys_reason, buildTags),
                solution = context.getString(R.string.chk_ext_test_keys_solution),
                technicalDetail = "ro.build.tags=$buildTags"
            )
        } else {
            DetectionResult(
                id = "extra_test_keys",
                name = context.getString(R.string.chk_ext_test_keys_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_test_keys_desc_nd),
                detailedReason = context.getString(R.string.chk_ext_test_keys_reason_nd, buildTags),
                solution = context.getString(R.string.no_action_required),
                technicalDetail = "ro.build.tags=$buildTags"
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 9: OEM unlock allowed / FRP bypass indicators
    // ----------------------------------------------------------------
    private fun checkOemUnlockAllowed(): DetectionResult {
        // Settings.Global.OEM_UNLOCK_ALLOWED requires privileged permission to read;
        // use system property fallback instead.
        val oemUnlockSupported = getSystemProperty("ro.oem_unlock_supported")
        val oemUnlockAllowed = getSystemProperty("sys.oem_unlock_allowed")
        val frpState = getSystemProperty("ro.frp.pst")

        val indicators = mutableListOf<String>()
        if (oemUnlockSupported == "1") indicators.add("ro.oem_unlock_supported=1")
        if (oemUnlockAllowed == "1") indicators.add("sys.oem_unlock_allowed=1")
        if (frpState.isNotEmpty()) indicators.add("ro.frp.pst=$frpState")

        // Also try to read via Settings.Global (needs no root but may be null)
        try {
            val settingValue = Settings.Global.getString(
                context.contentResolver, "oem_unlock_allowed"
            )
            if (settingValue == "1") indicators.add("Settings.Global.oem_unlock_allowed=1")
        } catch (_: Exception) {}

        return if (oemUnlockAllowed == "1" ||
            Settings.Global.getString(context.contentResolver, "oem_unlock_allowed") == "1"
        ) {
            DetectionResult(
                id = "oem_unlock",
                name = context.getString(R.string.chk_ext_oem_unlock_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_oem_unlock_desc),
                detailedReason = context.getString(R.string.chk_ext_oem_unlock_reason, indicators.joinToString(", ")),
                solution = context.getString(R.string.chk_ext_oem_unlock_solution),
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "oem_unlock",
                name = context.getString(R.string.chk_ext_oem_unlock_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_oem_unlock_desc_nd),
                detailedReason = context.getString(R.string.chk_ext_oem_unlock_reason_nd),
                solution = context.getString(R.string.no_action_required),
                technicalDetail = indicators.joinToString("; ").ifEmpty { "no indicators" }
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 10: Mock location provider enabled
    // ----------------------------------------------------------------
    @Suppress("DEPRECATION")
    private fun checkMockLocationsEnabled(): DetectionResult {
        return try {
            // ALLOW_MOCK_LOCATION was deprecated in API 23; kept for completeness as a fallback
            val allowMock = Settings.Secure.getInt(
                context.contentResolver, Settings.Secure.ALLOW_MOCK_LOCATION, 0
            )
            val mockLocationApp = Settings.Secure.getString(
                context.contentResolver, "mock_location"
            )
            val isMockEnabled = allowMock == 1 || (!mockLocationApp.isNullOrEmpty() &&
                mockLocationApp != "0" && mockLocationApp != "null")

            if (isMockEnabled) {
                val detail = buildString {
                    if (allowMock == 1) append("allow_mock_location=1 ")
                    if (!mockLocationApp.isNullOrEmpty()) append("mock_location_app=$mockLocationApp")
                }
                DetectionResult(
                    id = "mock_location",
                    name = context.getString(R.string.chk_ext_mock_loc_name),
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_mock_loc_desc),
                    detailedReason = context.getString(R.string.chk_ext_mock_loc_reason, detail),
                    solution = context.getString(R.string.chk_ext_mock_loc_solution),
                    technicalDetail = detail.trim()
                )
            } else {
                DetectionResult(
                    id = "mock_location",
                    name = context.getString(R.string.chk_ext_mock_loc_name_nd),
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_mock_loc_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_mock_loc_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "mock_location",
                name = context.getString(R.string.chk_ext_mock_loc_name_nd),
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_mock_loc_desc_error),
                detailedReason = context.getString(R.string.err_detail_query_failed, "Settings", e.message ?: ""),
                solution = context.getString(R.string.chk_ext_mock_loc_solution_error)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 11: ADB over Wi-Fi (port 5555 listening in /proc/net/tcp)
    // ----------------------------------------------------------------
    private fun checkWirelessAdb(): DetectionResult {
        val adbPorts = setOf(5555, 5037)
        val openPorts = mutableListOf<Int>()
        listOf("/proc/net/tcp", "/proc/net/tcp6").forEach { file ->
            try {
                File(file).readLines().drop(1).forEach { line ->
                    val parts = line.trim().split("\\s+".toRegex())
                    if (parts.size >= 4 && parts[3] == "0A") { // 0A = TCP_LISTEN (decimal 10 in hex)
                        val portHex = parts[1].split(":").lastOrNull() ?: return@forEach
                        try {
                            val port = portHex.toInt(16)
                            if (port in adbPorts && port !in openPorts) openPorts.add(port)
                        } catch (_: NumberFormatException) {}
                    }
                }
            } catch (_: Exception) {}
        }
        return if (openPorts.isNotEmpty()) {
            DetectionResult(
                id = "wireless_adb",
                name = context.getString(R.string.chk_ext_wireless_adb_name),
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_wireless_adb_desc),
                detailedReason = context.getString(R.string.chk_ext_wireless_adb_reason, openPorts.joinToString(", ")),
                solution = context.getString(R.string.chk_ext_wireless_adb_solution),
                technicalDetail = "Listening ports: ${openPorts.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "wireless_adb",
                name = context.getString(R.string.chk_ext_wireless_adb_name_nd),
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_wireless_adb_desc_nd),
                detailedReason = context.getString(R.string.chk_ext_wireless_adb_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 12: BusyBox binary presence
    // ----------------------------------------------------------------
    private fun checkBusyBoxInstalled(): DetectionResult {
        val busyboxPaths = listOf(
            "/system/bin/busybox",
            "/system/xbin/busybox",
            "/sbin/busybox",
            "/vendor/bin/busybox",
            "/data/local/busybox",
            "/data/local/tmp/busybox",
            "/data/local/xbin/busybox"
        )
        val found = busyboxPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "extra_busybox",
                name = context.getString(R.string.chk_ext_busybox_name),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_busybox_desc),
                detailedReason = context.getString(R.string.chk_ext_busybox_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_ext_busybox_solution),
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "extra_busybox",
                name = context.getString(R.string.chk_ext_busybox_name_nd),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_busybox_desc_nd),
                detailedReason = context.getString(R.string.chk_ext_busybox_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 13: SUID bit on su binary (world-executable + setuid)
    // ----------------------------------------------------------------
    private fun checkSuBinarySuid(): DetectionResult {
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "/vendor/bin/su",
            "/data/local/su",
            "/data/local/tmp/su",
            "/data/local/xbin/su"
        )
        val suidFound = mutableListOf<String>()
        suPaths.forEach { path ->
            try {
                val f = File(path)
                if (f.exists()) {
                    // canExecute() is insufficient to detect SUID; use stat via getprop fallback
                    // Attempt to read the file - if we can AND it's setuid root, that's a strong signal
                    val process = Runtime.getRuntime().exec(arrayOf("ls", "-l", path))
                    val output = BufferedReader(InputStreamReader(process.inputStream)).readLine() ?: ""
                    process.waitFor()
                    // ls -l output: first 10 chars are permissions, e.g. "---s--x--x"
                    // The owner-execute bit (index 3) is 's' or 'S' when the SUID bit is set.
                    val permChars = output.takeWhile { it in "-rwxsStTlpdbcD" }
                    if (permChars.length >= 4 && (permChars[3] == 's' || permChars[3] == 'S')) {
                        suidFound.add(path)
                    }
                }
            } catch (_: Exception) {
                // File exists but we couldn't stat — still a signal
                if (File(path).exists()) suidFound.add("$path (stat failed)")
            }
        }
        return if (suidFound.isNotEmpty()) {
            DetectionResult(
                id = "su_suid",
                name = context.getString(R.string.chk_ext_su_suid_name),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ext_su_suid_desc),
                detailedReason = context.getString(R.string.chk_ext_su_suid_reason, suidFound.joinToString(", ")),
                solution = context.getString(R.string.chk_ext_su_suid_solution),
                technicalDetail = "SUID su: ${suidFound.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "su_suid",
                name = context.getString(R.string.chk_ext_su_suid_name_nd),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ext_su_suid_desc_nd),
                detailedReason = context.getString(R.string.chk_ext_su_suid_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 14: Shamiko / Zygisk-Assistant / ReZygisk hide modules
    // ----------------------------------------------------------------
    private fun checkShamikoZygiskAssist(): DetectionResult {
        val hideModuleDirs = listOf(
            "/data/adb/modules/shamiko",
            "/data/adb/modules/zygisk_shamiko",
            "/data/adb/modules/zygiskassist",
            "/data/adb/modules/zygisk_assistant",
            "/data/adb/modules/rezygisk",
            "/data/adb/modules/play_integrity_fix",
            "/data/adb/modules/playintegrityfix",
            "/data/adb/modules/tricky_store",
            "/data/adb/modules/minifakebool",
            "/data/adb/modules/shamiko-release"
        )
        val hidePackages = listOf(
            "io.github.huskydg.magisk",            // Magisk Delta (built-in Shamiko)
            "app.revanced.android.youtube",        // ReVanced (root patch)
            "io.github.vvb2060.magisk"             // Another Magisk fork
        )
        val foundDirs = hideModuleDirs.filter { File(it).exists() }
        val foundPkgs = hidePackages.filter { packageExists(it) }

        return if (foundDirs.isNotEmpty() || foundPkgs.isNotEmpty()) {
            val all = mutableListOf<String>()
            foundDirs.forEach { all.add(it.substringAfterLast("/")) }
            foundPkgs.forEach { all.add(it) }
            DetectionResult(
                id = "shamiko_zygiskassist",
                name = context.getString(R.string.chk_ext_shamiko_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ext_shamiko_desc),
                detailedReason = context.getString(R.string.chk_ext_shamiko_reason, all.joinToString(", ")),
                solution = context.getString(R.string.chk_ext_shamiko_solution),
                technicalDetail = "Dirs: ${foundDirs.joinToString("; ")} | Pkgs: ${foundPkgs.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "shamiko_zygiskassist",
                name = context.getString(R.string.chk_ext_shamiko_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_ext_shamiko_desc_nd),
                detailedReason = context.getString(R.string.chk_ext_shamiko_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 15: Hidden bind-mounts over /system in /proc/self/mountinfo
    // ----------------------------------------------------------------
    private fun checkHiddenSystemBindMounts(): DetectionResult {
        return try {
            val mountinfo = File("/proc/self/mountinfo").readText()
            // Only flag bind-mounts over /system, /vendor, or /product whose source
            // originates from the Magisk/KSU working directory (/data/adb). Generic
            // /data mounts, OEM overlayfs, and vendor bind-mounts are excluded to
            // avoid false positives on stock and carrier-customised devices.
            // mountinfo(5) format:
            //   id parent devno root mountPoint mountOpts [optionalFields...] - fsType source superOpts
            // The "-" separator marks the end of variable optional fields.
            val suspiciousBinds = mutableListOf<String>()
            mountinfo.lines().forEach { line ->
                val parts = line.trim().split(" ")
                if (parts.size < 7) return@forEach
                val mountPoint = parts[4]

                // Find the "-" separator to locate fsType and source correctly
                val sepIdx = parts.indexOf("-")
                if (sepIdx < 0 || sepIdx + 2 >= parts.size) return@forEach
                val source = parts[sepIdx + 2]

                // Only flag mounts over system partitions that explicitly come from
                // the Magisk/KSU module install path (/data/adb).
                val isSystemPath = mountPoint.startsWith("/system") ||
                    mountPoint.startsWith("/vendor") || mountPoint.startsWith("/product")
                val isFromRootFramework = source.startsWith("/data/adb")

                if (isSystemPath && isFromRootFramework && !suspiciousBinds.contains(mountPoint)) {
                    suspiciousBinds.add("$mountPoint←$source")
                }
            }
            if (suspiciousBinds.isNotEmpty()) {
                DetectionResult(
                    id = "hidden_system_mounts",
                    name = context.getString(R.string.chk_ext_sys_mounts_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_sys_mounts_desc),
                    detailedReason = context.getString(R.string.chk_ext_sys_mounts_reason, suspiciousBinds.take(5).joinToString(", ")),
                    solution = context.getString(R.string.chk_ext_sys_mounts_solution),
                    technicalDetail = "Mounts: ${suspiciousBinds.take(10).joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "hidden_system_mounts",
                    name = context.getString(R.string.chk_ext_sys_mounts_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_sys_mounts_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_sys_mounts_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "hidden_system_mounts",
                name = context.getString(R.string.chk_ext_sys_mounts_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_sys_mounts_desc_error),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.chk_ext_sys_mounts_solution_error)
            )
        }
    }

    // ---- Utilities ----

    /**
     * Check 16: /data/local/tmp directory anomalies.
     *
     * On a clean Android device /data/local/tmp is owned by shell (uid=2000, gid=2000)
     * with permissions 0771. Root frameworks (KSU, Magisk) or tool chains sometimes change
     * the ownership to root or alter permissions. The inode number also tells a story:
     * if it's very large (>10000) the directory was likely deleted and recreated (SUSFS
     * may spoof this; a legitimate new device will have small inode numbers).
     *
     * Inspired by Chunqiu Detector items "Suspicious Surroundings (a/b/c)" and "Futile hide".
     */
    private fun checkDataLocalTmpAnomalies(): DetectionResult {
        val tmpDir = "/data/local/tmp"
        val anomalies = mutableListOf<String>()
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("stat", "-c", "%u %g %a %i", tmpDir))
            val output = BufferedReader(InputStreamReader(process.inputStream)).readLine()?.trim() ?: ""
            process.waitFor()
            if (output.isNotEmpty()) {
                val parts = output.split(" ")
                if (parts.size >= 4) {
                    val uid = parts[0].toIntOrNull() ?: -1
                    val gid = parts[1].toIntOrNull() ?: -1
                    val perms = parts[2]
                    val inode = parts[3].toLongOrNull() ?: -1L
                    // (a) Owner should be shell (uid=2000), not root (uid=0)
                    if (uid == 0) anomalies.add("owner=root(uid=0) expected shell(uid=2000)")
                    // (b) Group should not be root either
                    if (gid == 0) anomalies.add("group=root(gid=0) expected shell(gid=2000)")
                    // (c) Permissions should be 771
                    if (perms != "771" && perms.isNotEmpty()) anomalies.add("permissions=$perms (expected 771)")
                    // (b) Inode > 10000 implies deletion/recreation
                    if (inode > 10000L) anomalies.add("inode=$inode (>10000 indicates prior deletion)")
                }
            }
            if (anomalies.isNotEmpty()) {
                DetectionResult(
                    id = "tmp_anomaly",
                    name = context.getString(R.string.chk_ext_tmp_anomaly_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_tmp_anomaly_desc),
                    detailedReason = context.getString(R.string.chk_ext_tmp_anomaly_reason, anomalies.joinToString("; ")),
                    solution = context.getString(R.string.chk_ext_tmp_anomaly_solution),
                    technicalDetail = "$tmpDir: ${anomalies.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "tmp_anomaly",
                    name = context.getString(R.string.chk_ext_tmp_anomaly_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_tmp_anomaly_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_tmp_anomaly_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "tmp_anomaly",
                name = context.getString(R.string.chk_ext_tmp_anomaly_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_tmp_anomaly_desc_nd),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    /**
     * Check 17: Suspicious tool files at well-known hacking/tweaking paths.
     *
     * Various tools leave artefacts at predictable paths under /data/local/tmp and
     * /data/local. The Chunqiu Detector (and similar security checks) enumerate these
     * paths. Finding any of them is a strong signal that modification tools have been
     * run on this device.
     */
    private fun checkSuspiciousToolFiles(): DetectionResult {
        val suspiciousPaths = listOf(
            // Stryker / tweak frameworks
            "/data/local/stryker",
            // Luckys helper files
            "/data/local/tmp/luckys",
            "/data/local/luckys",
            // Accessibility/input hooks
            "/data/local/tmp/input_devices",
            // HyperCeiler MIUI tweak
            "/data/local/tmp/HyperCeiler",
            // simpleHook Xposed helper
            "/data/local/tmp/simpleHook",
            // DisabledAllGoogleServices module
            "/data/local/tmp/DisabledAllGoogleServices",
            // MIO framework
            "/data/local/MIO",
            // DNA custom framework
            "/data/DNA",
            // Cleaner starter scripts
            "/data/local/tmp/cleaner_starter",
            // ByYang tools
            "/data/local/tmp/byyang",
            // Mount mask/mark files (used by various Zygisk modules)
            "/data/local/tmp/mount_mask",
            "/data/local/tmp/mount_mark",
            // Script temp files
            "/data/local/tmp/scriptTMP",
            // Horae control log (Horae scheduler)
            "/data/local/tmp/horae_control.log",
            // GPU/swap config files placed by performance tweaks
            "/data/gpu_freq_table.conf",
            "/data/swap_config.conf",
            // resetprop binary in tmp (dropped by some Magisk modules)
            "/data/local/tmp/resetprop",
            // System retention & freezer (aggressive battery managers)
            "/data/system/AppRetention",
            "/data/system/NoActive",
            "/data/system/Freezer",
            // Naki folder on external storage
            "/storage/emulated/0/Android/naki"
        )
        val found = suspiciousPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "suspicious_tool_files",
                name = context.getString(R.string.chk_ext_tool_files_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_tool_files_desc),
                detailedReason = context.getString(R.string.chk_ext_tool_files_reason, found.take(5).joinToString(", ")),
                solution = context.getString(R.string.chk_ext_tool_files_solution),
                technicalDetail = "Found: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "suspicious_tool_files",
                name = context.getString(R.string.chk_ext_tool_files_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_tool_files_desc_nd),
                detailedReason = context.getString(R.string.chk_ext_tool_files_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    /**
     * Check 18: /debug_ramdisk inconsistent mount.
     *
     * Android's boot process uses a ramdisk whose contents are available at /debug_ramdisk
     * on non-production builds. On a stock device this path either does not exist or is
     * unmounted after early init. If it still appears as a mount point (visible in
     * /proc/self/mounts) the device either has a non-standard boot image or a root framework
     * has deliberately left it mounted, which can leak kernel debug symbols or provide a
     * writeable location in the root namespace.
     *
     * Chunqiu Detector item: "不一致的挂载/debug_ramdisk"
     */
    private fun checkDebugRamdiskMount(): DetectionResult {
        return try {
            val mounts = File("/proc/self/mounts").readText()
            val debugRamdiskMounted = mounts.lines().any { line ->
                val parts = line.trim().split("\\s+".toRegex())
                parts.size >= 2 && parts[1] == "/debug_ramdisk"
            }
            if (debugRamdiskMounted) {
                DetectionResult(
                    id = "debug_ramdisk_mount",
                    name = context.getString(R.string.chk_ext_debug_ramdisk_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_debug_ramdisk_desc),
                    detailedReason = context.getString(R.string.chk_ext_debug_ramdisk_reason),
                    solution = context.getString(R.string.chk_ext_debug_ramdisk_solution),
                    technicalDetail = "/debug_ramdisk is still mounted"
                )
            } else {
                DetectionResult(
                    id = "debug_ramdisk_mount",
                    name = context.getString(R.string.chk_ext_debug_ramdisk_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_debug_ramdisk_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_debug_ramdisk_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "debug_ramdisk_mount",
                name = context.getString(R.string.chk_ext_debug_ramdisk_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_debug_ramdisk_desc_nd),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    /**
     * Check 19: MT Manager artefacts (MT2 folder).
     *
     * MT Manager (a popular Android file manager / APK editor) creates an "mt2" folder
     * in the root of internal storage by default. When this folder exists it confirms
     * MT Manager has been run on the device, which is a strong indicator that APK
     * patching, module injection, or other tampering may have occurred.
     *
     * Chunqiu Detector item: "MT管理器(MT2文件夹)/异常文件"
     */
    private fun checkMtManagerFiles(): DetectionResult {
        val mtPaths = listOf(
            "/sdcard/mt2",
            "/storage/emulated/0/mt2"
        )
        val found = mtPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "mt_manager_files",
                name = context.getString(R.string.chk_ext_mt_manager_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_mt_manager_desc),
                detailedReason = context.getString(R.string.chk_ext_mt_manager_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_ext_mt_manager_solution),
                technicalDetail = "MT2 paths found: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "mt_manager_files",
                name = context.getString(R.string.chk_ext_mt_manager_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_mt_manager_desc_nd),
                detailedReason = context.getString(R.string.chk_ext_mt_manager_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    /**
     * Check 20: Kernel version with -dirty suffix.
     *
     * When a kernel is compiled locally (outside of an official build system) the
     * build system appends "-dirty" to the kernel version string if there are any
     * uncommitted git changes. This suffix in /proc/version is a reliable indicator
     * of a third-party or self-compiled kernel, which is commonly used alongside
     * custom ROMs and root setups.
     *
     * Chunqiu Detector item: "第三方ROM/自编译内核"
     */
    private fun checkKernelDirtySuffix(): DetectionResult {
        return try {
            val version = File("/proc/version").readText().trim()
            val isDirty = version.contains("-dirty", ignoreCase = true)
            if (isDirty) {
                DetectionResult(
                    id = "kernel_dirty",
                    name = context.getString(R.string.chk_ext_kernel_dirty_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_kernel_dirty_desc),
                    detailedReason = context.getString(R.string.chk_ext_kernel_dirty_reason, version.take(120)),
                    solution = context.getString(R.string.chk_ext_kernel_dirty_solution),
                    technicalDetail = "Kernel: ${version.take(120)}"
                )
            } else {
                DetectionResult(
                    id = "kernel_dirty",
                    name = context.getString(R.string.chk_ext_kernel_dirty_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_kernel_dirty_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_kernel_dirty_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "kernel_dirty",
                name = context.getString(R.string.chk_ext_kernel_dirty_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_kernel_dirty_desc_nd),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    /**
     * Check 21: dex2oat anomaly detection.
     *
     * LSPosed and some Xposed forks inject code by creating a custom dex2oat compiler filter
     * or leaving behind residual .odex/.oat artefacts in unexpected locations. Additionally,
     * LSPosed rewrites the dex2oat binary path in system properties so that its own wrapper
     * is called instead. Detecting a non-standard dex2oat path or the presence of LSPosed
     * dex2oat helper files is a reliable hook-framework indicator.
     *
     * Chunqiu Detector item: "Miscellaneous Check（a）" — dex2oat (LSP problem)
     */
    private fun checkDex2oatAnomaly(): DetectionResult {
        val anomalies = mutableListOf<String>()
        return try {
            // Check 1: non-standard compiler filter
            val dex2oatFilter = getSystemProperty("dalvik.vm.dex2oat-filter")
            val knownFilters = setOf("speed-profile", "speed", "quicken", "space-profile", "space",
                "everything", "verify", "interpret-only", "time", "")
            if (dex2oatFilter.isNotEmpty() && dex2oatFilter !in knownFilters) {
                anomalies.add("dalvik.vm.dex2oat-filter=$dex2oatFilter (non-standard)")
            }
            // Check 2: LSPosed dex2oat wrapper files
            val lspDex2oatPaths = listOf(
                "/data/adb/lspd/dex2oat",
                "/data/adb/lspd/bin/dex2oat",
                "/data/misc/lspd/dex2oat",
                "/data/adb/modules/zygisk_lsposed/dex2oat"
            )
            lspDex2oatPaths.filter { File(it).exists() }.forEach { anomalies.add("LSPosed dex2oat wrapper: $it") }
            // Check 3: lspd dex2oat mapping in /proc/self/maps
            try {
                val maps = File("/proc/self/maps").readText()
                if (maps.contains("lspd") && maps.contains("dex2oat", ignoreCase = true)) {
                    anomalies.add("lspd dex2oat mapping in /proc/self/maps")
                }
            } catch (_: Exception) {}
            // Check 4: native stat() probe (bypasses Java-layer File.exists() hooks)
            val nativeFindings = NativeDetector.detectDex2oatNative()
            if (nativeFindings.isNotEmpty()) {
                nativeFindings.split("; ").filter { it.isNotEmpty() }.forEach { anomalies.add("native: $it") }
            }

            if (anomalies.isNotEmpty()) {
                DetectionResult(
                    id = "dex2oat_anomaly",
                    name = context.getString(R.string.chk_ext_dex2oat_name),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_dex2oat_desc),
                    detailedReason = context.getString(R.string.chk_ext_dex2oat_reason, anomalies.joinToString("; ")),
                    solution = context.getString(R.string.chk_ext_dex2oat_solution),
                    technicalDetail = anomalies.joinToString("; ")
                )
            } else {
                DetectionResult(
                    id = "dex2oat_anomaly",
                    name = context.getString(R.string.chk_ext_dex2oat_name_nd),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_dex2oat_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_dex2oat_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "dex2oat_anomaly",
                name = context.getString(R.string.chk_ext_dex2oat_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_dex2oat_desc_nd),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    /**
     * Check 22: Scene toolkit port occupancy detection.
     *
     * Scene (一个场景/Fkscene) is a popular Android performance/battery tweaking app
     * that runs an accessibility service and a local HTTP server on a fixed port (typically
     * 18080 or 18081). Detecting its package name or an open socket at these ports
     * indicates Scene is running.
     *
     * Chunqiu Detector item: "检测到Scene端口占用"
     */
    private fun checkScenePortOccupied(): DetectionResult {
        val scenePackages = listOf("com.omarea.vtools", "com.omarea.scene", "com.omarea.vtools.pro")
        val foundPkgs = scenePackages.filter { packageExists(it) }
        val scenePorts = listOf(18080, 18081, 9999)
        val openPorts = mutableListOf<Int>()
        return try {
            listOf("/proc/net/tcp", "/proc/net/tcp6").forEach { tcpFile ->
                try {
                    File(tcpFile).readLines().drop(1).forEach { line ->
                        val parts = line.trim().split("\\s+".toRegex())
                        if (parts.size >= 4 && parts[3] == "0A") {
                            val portHex = parts[1].substringAfterLast(":")
                            val port = portHex.toIntOrNull(16) ?: return@forEach
                            if (port in scenePorts) openPorts.add(port)
                        }
                    }
                } catch (_: Exception) {}
            }
            val detected = foundPkgs.isNotEmpty() || openPorts.isNotEmpty()
            if (detected) {
                val indicators = mutableListOf<String>()
                if (foundPkgs.isNotEmpty()) indicators.add("packages: ${foundPkgs.joinToString(", ")}")
                if (openPorts.isNotEmpty()) indicators.add("ports: ${openPorts.joinToString(", ")}")
                DetectionResult(
                    id = "scene_port",
                    name = context.getString(R.string.chk_ext_scene_port_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.LOW,
                    description = context.getString(R.string.chk_ext_scene_port_desc),
                    detailedReason = context.getString(R.string.chk_ext_scene_port_reason, indicators.joinToString("; ")),
                    solution = context.getString(R.string.chk_ext_scene_port_solution),
                    technicalDetail = indicators.joinToString("; ")
                )
            } else {
                DetectionResult(
                    id = "scene_port",
                    name = context.getString(R.string.chk_ext_scene_port_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.LOW,
                    description = context.getString(R.string.chk_ext_scene_port_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_scene_port_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "scene_port",
                name = context.getString(R.string.chk_ext_scene_port_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.LOW,
                description = context.getString(R.string.chk_ext_scene_port_desc_nd),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    /**
     * Check 23: Hidden process group detection.
     *
     * Some root-related processes hide from the normal process list but leave traces
     * in /proc. By reading /proc directly and looking for PIDs whose thread-group leader
     * (Tgid) is not itself visible as a /proc entry, we can expose hidden processes.
     *
     * Chunqiu Detector item: "异常进程" / "异常进程组"
     */
    private fun checkHiddenProcessGroups(): DetectionResult {
        val suspiciousProcs = mutableListOf<String>()
        return try {
            val procDir = File("/proc")
            val pidDirs = procDir.listFiles { _, name ->
                name.all { c -> c.isDigit() }
            } ?: emptyArray()
            val allPids = pidDirs.map { it.name.toInt() }.toSet()
            pidDirs.forEach { pidDir ->
                try {
                    val statusFile = File(pidDir, "status")
                    if (!statusFile.exists()) return@forEach
                    val statusText = statusFile.readText()
                    val name = statusText.lines().firstOrNull { it.startsWith("Name:") }
                        ?.removePrefix("Name:")?.trim() ?: return@forEach
                    val tgid = statusText.lines().firstOrNull { it.startsWith("Tgid:") }
                        ?.removePrefix("Tgid:")?.trim()?.toIntOrNull() ?: return@forEach
                    val pid = pidDir.name.toInt()
                    if (tgid != pid && tgid !in allPids) {
                        suspiciousProcs.add("$name(pid=$pid,tgid=$tgid missing)")
                    }
                } catch (_: Exception) {}
            }
            if (suspiciousProcs.isNotEmpty()) {
                DetectionResult(
                    id = "hidden_process_groups",
                    name = context.getString(R.string.chk_ext_hidden_proc_name),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_hidden_proc_desc),
                    detailedReason = context.getString(R.string.chk_ext_hidden_proc_reason, suspiciousProcs.take(5).joinToString(", ")),
                    solution = context.getString(R.string.chk_ext_hidden_proc_solution),
                    technicalDetail = "Hidden groups: ${suspiciousProcs.take(10).joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "hidden_process_groups",
                    name = context.getString(R.string.chk_ext_hidden_proc_name_nd),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_hidden_proc_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_hidden_proc_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "hidden_process_groups",
                name = context.getString(R.string.chk_ext_hidden_proc_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_hidden_proc_desc_nd),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    /**
     * Check 24: Netlink socket anomaly detection.
     *
     * KernelSU communicates with the kernel via Netlink sockets using custom protocol
     * families. Listing /proc/net/netlink for non-standard protocol numbers (outside
     * the known Android set) signals kernel-level root activity.
     *
     * Chunqiu Detector item: "Netlink socket anomaly"
     */
    private fun checkNetlinkSocketAnomaly(): DetectionResult {
        val standardProtos = setOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22)
        val anomalies = mutableListOf<String>()
        return try {
            val netlinkFile = File("/proc/net/netlink")
            if (netlinkFile.exists()) {
                val lines = netlinkFile.readLines().drop(1)
                val protoCounts = mutableMapOf<Int, Int>()
                lines.forEach { line ->
                    val parts = line.trim().split("\\s+".toRegex())
                    if (parts.size >= 3) {
                        val proto = parts[1].toIntOrNull() ?: return@forEach
                        protoCounts[proto] = (protoCounts[proto] ?: 0) + 1
                    }
                }
                protoCounts.forEach { (proto, count) ->
                    if (proto !in standardProtos) {
                        anomalies.add("non-standard netlink proto=$proto (${count} socket(s))")
                    }
                }
                protoCounts.forEach { (proto, count) ->
                    if (count > 20 && proto in standardProtos) {
                        anomalies.add("high socket count: proto=$proto count=$count")
                    }
                }
            }
            // Also run native probe (uses raw read(2) syscalls, harder to hook)
            val nativeFindings = NativeDetector.detectNetlinkNative()
            if (nativeFindings.isNotEmpty()) {
                nativeFindings.split("; ").filter { it.isNotEmpty() }.forEach { f ->
                    val entry = "native: $f"
                    if (!anomalies.contains(entry)) anomalies.add(entry)
                }
            }
            if (anomalies.isNotEmpty()) {
                DetectionResult(
                    id = "netlink_anomaly",
                    name = context.getString(R.string.chk_ext_netlink_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_netlink_desc),
                    detailedReason = context.getString(R.string.chk_ext_netlink_reason, anomalies.joinToString("; ")),
                    solution = context.getString(R.string.chk_ext_netlink_solution),
                    technicalDetail = anomalies.joinToString("; ")
                )
            } else {
                DetectionResult(
                    id = "netlink_anomaly",
                    name = context.getString(R.string.chk_ext_netlink_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_ext_netlink_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_netlink_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "netlink_anomaly",
                name = context.getString(R.string.chk_ext_netlink_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ext_netlink_desc_nd),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    /**
     * Check 25: Audit log process detection.
     *
     * Reads kernel SELinux audit log entries (AVC denials) from /dev/kmsg via the
     * native layer (raw open/read syscalls that bypass Java-layer hooks).  Root
     * daemon processes (magiskd, lspd, kpatchd) leave distinctive SELinux context
     * strings in AVC denials even when hidden from the process table.
     *
     * The article references "审计日志漏洞读取(avc)" — ZN-AuditPatch and SUSFS
     * are the typical countermeasures.
     *
     * Chunqiu Detector item: "ROOT进程" (via audit log)
     */
    private fun checkAuditLogProcesses(): DetectionResult {
        val findings = mutableListOf<String>()
        return try {
            // Strategy 1: native /dev/kmsg + logcat probe (bypasses Java hooks)
            val nativeResult = NativeDetector.detectAuditLog()
            if (nativeResult.isNotEmpty()) {
                nativeResult.split("; ").filter { it.isNotEmpty() }.forEach { findings.add(it) }
            }
            // Strategy 2: Java-level logcat -b kernel fallback (broader compatibility)
            if (findings.isEmpty()) {
                try {
                    val proc = Runtime.getRuntime().exec(arrayOf("logcat", "-b", "kernel", "-d", "-t", "200"))
                    val reader = BufferedReader(InputStreamReader(proc.inputStream))
                    val rootContexts = listOf("u:r:magisk:", "u:r:su:", "u:r:zygisk:")
                    val rootComms = listOf("magiskd", "magisk64", "magisk32", "lspd", "kpatchd")
                    var line: String?
                    var count = 0
                    while (reader.readLine().also { line = it } != null && count < 500) {
                        val l = line ?: break
                        if (l.contains("avc:") || l.contains("type=AVC")) {
                            rootContexts.forEach { ctx ->
                                if (l.contains(ctx)) findings.add("avc_ctx:$ctx")
                            }
                            rootComms.forEach { comm ->
                                if (l.contains("comm=\"$comm\"")) findings.add("avc_comm:$comm")
                            }
                        }
                        count++
                    }
                    reader.close()
                    proc.destroy()
                } catch (_: Exception) {}
            }

            if (findings.isNotEmpty()) {
                val deduped = findings.distinct()
                DetectionResult(
                    id = "audit_log_root_process",
                    name = context.getString(R.string.chk_ext_audit_log_name),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_audit_log_desc),
                    detailedReason = context.getString(R.string.chk_ext_audit_log_reason, deduped.take(5).joinToString("; ")),
                    solution = context.getString(R.string.chk_ext_audit_log_solution),
                    technicalDetail = deduped.take(10).joinToString("; ")
                )
            } else {
                DetectionResult(
                    id = "audit_log_root_process",
                    name = context.getString(R.string.chk_ext_audit_log_name_nd),
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_ext_audit_log_desc_nd),
                    detailedReason = context.getString(R.string.chk_ext_audit_log_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "audit_log_root_process",
                name = context.getString(R.string.chk_ext_audit_log_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ext_audit_log_desc_nd),
                detailedReason = context.getString(R.string.err_detail_failed, e.message ?: ""),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // ---- Utilities ----

    private fun getSystemProperty(key: String): String {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
            BufferedReader(InputStreamReader(process.inputStream)).readLine()?.trim() ?: ""
        } catch (_: Exception) {
            ""
        }
    }

    private fun packageExists(packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }
}
