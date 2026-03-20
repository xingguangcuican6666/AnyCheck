package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
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
        checkHiddenSystemBindMounts()
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
                    name = "LD_PRELOAD / LD_LIBRARY_PATH Set",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "Linker environment variable injection detected.",
                    detailedReason = "Found: ${suspicious.joinToString(", ")}. " +
                        "Setting LD_PRELOAD causes the dynamic linker to load an attacker-chosen " +
                        "library before all others, enabling function interception in any process. " +
                        "This is used by Frida gadget, Substrate-style hooks, and some su wrappers.",
                    solution = "Remove any LD_PRELOAD/LD_LIBRARY_PATH from the environment. " +
                        "Uninstall any hooking framework that injects via the linker.",
                    technicalDetail = suspicious.joinToString("; ")
                )
            } else {
                DetectionResult(
                    id = "ld_preload",
                    name = "LD_PRELOAD Environment",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "No LD_PRELOAD injection detected.",
                    detailedReason = "LD_PRELOAD and LD_LIBRARY_PATH are not set to suspicious values.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "ld_preload",
                name = "LD_PRELOAD Environment",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = "Could not read process environment.",
                detailedReason = "Failed to read /proc/self/environ: ${e.message}",
                solution = "Ensure /proc/self/environ is accessible."
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
                    name = "Elevated Linux Capabilities",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "Process has non-zero Linux capabilities.",
                    detailedReason = "CapPrm=$capPrm, CapEff=$capEff. " +
                        "Normal Android apps run with zero capabilities. " +
                        "Non-zero values indicate this process was granted elevated Linux privileges, " +
                        "which can happen when su or a root framework manipulates the process.",
                    solution = "Revoke elevated capabilities. These are normally granted by root frameworks.",
                    technicalDetail = "CapPrm=$capPrm CapEff=$capEff"
                )
            } else {
                DetectionResult(
                    id = "capabilities",
                    name = "Linux Capabilities",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "Process has no elevated Linux capabilities.",
                    detailedReason = "CapPrm=0 and CapEff=0 — normal for a sandboxed Android app.",
                    solution = "No action required.",
                    technicalDetail = "CapPrm=$capPrm CapEff=$capEff"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "capabilities",
                name = "Linux Capabilities",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not read process status.",
                detailedReason = "Failed: ${e.message}",
                solution = "Ensure /proc/self/status is accessible."
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
            // Only match paths that are clearly from root-framework working directories.
            // /data/adb/magisk and /data/adb/ksu are the canonical install paths used
            // by Magisk and KernelSU respectively. Vendor overlayfs mounts do not
            // reference these paths and are therefore excluded.
            val rootFrameworkSourcePrefixes = listOf(
                "/data/adb/magisk", "/data/adb/ksu", "/data/adb/modules",
                "/@magisk", "/@ksu"
            )
            val found = mutableListOf<String>()
            mountinfo.lines().forEach { line ->
                val sepIdx = line.indexOf(" - ")
                if (sepIdx < 0) return@forEach
                val source = line.substring(sepIdx + 3).trim().split(" ").getOrNull(1) ?: return@forEach
                if (rootFrameworkSourcePrefixes.any { source.startsWith(it) } &&
                    !found.contains(line.take(80))
                ) {
                    found.add(line.take(80))
                }
            }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "mountinfo_overlay",
                    name = "Magisk/KSU Overlay Mounts Detected",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "Root framework overlay mount entries found in /proc/self/mountinfo.",
                    detailedReason = "/proc/self/mountinfo shows ${found.size} mount entry/entries sourced " +
                        "from Magisk/KSU directories (/data/adb/magisk or /data/adb/ksu). " +
                        "These are bind-mounts created by the root framework's module system " +
                        "to overlay modified files over the original system partition.",
                    solution = "Remove root framework modules or uninstall the root framework entirely.",
                    technicalDetail = found.take(5).joinToString("\n")
                )
            } else {
                DetectionResult(
                    id = "mountinfo_overlay",
                    name = "Root Overlay Mounts",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "No Magisk/KSU overlay mounts found.",
                    detailedReason = "No root framework markers were found in /proc/self/mountinfo.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "mountinfo_overlay",
                name = "Root Overlay Mounts",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = "Could not read /proc/self/mountinfo.",
                detailedReason = "Failed: ${e.message}",
                solution = "Ensure /proc/self/mountinfo is accessible."
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
                    name = "tmpfs Mounted at /sbin",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "tmpfs is mounted over /sbin — legacy Magisk indicator.",
                    detailedReason = "Magisk versions prior to v24 mounted a tmpfs over /sbin to store its " +
                        "binaries and hide them from detection. " +
                        "A tmpfs on /sbin on a production device is a strong Magisk indicator.",
                    solution = "This is removed when Magisk is uninstalled.",
                    technicalDetail = "/sbin mounted as tmpfs"
                )
            } else {
                DetectionResult(
                    id = "sbin_tmpfs",
                    name = "tmpfs at /sbin",
                    category = DetectionCategory.MAGISK,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "No tmpfs mount at /sbin.",
                    detailedReason = "/sbin does not have a tmpfs mount.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "sbin_tmpfs",
                name = "tmpfs at /sbin",
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not read /proc/mounts.",
                detailedReason = "Failed: ${e.message}",
                solution = "Ensure /proc/mounts is accessible."
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
                    name = "Unexpected Root Processes",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "Unexpected processes running as uid=0 (root).",
                    detailedReason = "Found ${suspiciousRootProcs.size} unexpected root process(es): " +
                        "${suspiciousRootProcs.take(10).joinToString(", ")}. " +
                        "On a stock device, the set of uid=0 processes is fixed. " +
                        "Extra root processes indicate active root frameworks (magiskd, ksud, etc.).",
                    solution = "Stop or remove the root framework to eliminate unexpected root processes.",
                    technicalDetail = "Root processes: ${suspiciousRootProcs.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "privileged_processes",
                    name = "Privileged Processes",
                    category = DetectionCategory.ROOT_MANAGEMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "No unexpected uid=0 processes found.",
                    detailedReason = "Only expected system processes were found running as root.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "privileged_processes",
                name = "Privileged Processes",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not enumerate processes.",
                detailedReason = "Failed: ${e.message}",
                solution = "Ensure /proc is accessible."
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
                name = "Terminal / Hacking Apps Detected",
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "Terminal emulator or security tool apps installed.",
                detailedReason = "Found ${found.size} app(s): " +
                    found.values.joinToString(", ") + ". " +
                    "These apps provide terminal access, SSH, scripting environments, " +
                    "or advanced file system access. Many require or facilitate root access.",
                solution = "Uninstall terminal and hacking apps if not needed for legitimate use.",
                technicalDetail = found.keys.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "terminal_hacking_apps",
                name = "Terminal / Hacking Apps",
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "No terminal emulator or hacking apps detected.",
                detailedReason = "No known terminal or security tool packages were found.",
                solution = "No action required."
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
                    name = "Security Patch Very Outdated",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "Security patch is ${monthsOld} months old (>= 2 years).",
                    detailedReason = "Security patch level: $patchStr (${monthsOld} months ago). " +
                        "Rooted devices often avoid OTA updates to preserve root access, " +
                        "resulting in severely outdated security patches. " +
                        "An extremely old patch level exposes the device to known CVEs.",
                    solution = "Apply all available OTA/security updates.",
                    technicalDetail = "SECURITY_PATCH=$patchStr monthsOld=$monthsOld"
                )
                monthsOld >= 12 -> DetectionResult(
                    id = "security_patch_age",
                    name = "Security Patch Outdated",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = "Security patch is ${monthsOld} months old (>= 1 year).",
                    detailedReason = "Security patch level: $patchStr (${monthsOld} months ago). " +
                        "Keeping the patch level current is important for device security.",
                    solution = "Apply all available security updates from the manufacturer.",
                    technicalDetail = "SECURITY_PATCH=$patchStr monthsOld=$monthsOld"
                )
                else -> DetectionResult(
                    id = "security_patch_age",
                    name = "Security Patch Level",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = "Security patch level is reasonably current (< 12 months).",
                    detailedReason = "Patch date: $patchStr (${monthsOld} months ago).",
                    solution = "No action required.",
                    technicalDetail = "SECURITY_PATCH=$patchStr monthsOld=$monthsOld"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "security_patch_age",
                name = "Security Patch Level",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.MEDIUM,
                description = "Could not determine security patch age.",
                detailedReason = "Error: ${e.message}",
                solution = "Check Settings → About Phone → Android security patch level."
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
                name = "Test-Keys Build Detected",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Device is running a test-keys signed build.",
                detailedReason = "ro.build.tags=$buildTags. " +
                    "Production (retail) Android builds are signed with release keys and report 'release-keys'. " +
                    "'test-keys' means the build was signed with Android's publicly known AOSP test keys, " +
                    "which is typical for custom ROMs (LineageOS, AOSP builds) and developer images. " +
                    "Such builds often have root access or weaker security policies.",
                solution = "Use an OEM-provided, release-keys signed official ROM.",
                technicalDetail = "ro.build.tags=$buildTags"
            )
        } else {
            DetectionResult(
                id = "extra_test_keys",
                name = "Build Signing Keys",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Build is signed with release keys.",
                detailedReason = "ro.build.tags=$buildTags — not test-keys.",
                solution = "No action required.",
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
                name = "OEM Unlock Enabled",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "OEM unlock is currently enabled.",
                detailedReason = "OEM unlock enabled: ${indicators.joinToString(", ")}. " +
                    "When OEM unlock is allowed, the user can unlock the bootloader from Developer Options. " +
                    "An enabled OEM unlock setting indicates the device is prepared for rooting.",
                solution = "Disable OEM unlock via Settings → Developer Options → OEM unlocking → toggle off.",
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "oem_unlock",
                name = "OEM Unlock",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "OEM unlock does not appear to be enabled.",
                detailedReason = "No OEM unlock enabled indicators found.",
                solution = "No action required.",
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
                    name = "Mock Locations Enabled",
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = "Mock location provider is enabled.",
                    detailedReason = "Mock locations allow any app to supply fake GPS coordinates. " +
                        "This is commonly used for GPS spoofing and game cheating. " +
                        "Detail: $detail",
                    solution = "Disable mock location: Settings → Developer Options → Mock location app → None.",
                    technicalDetail = detail.trim()
                )
            } else {
                DetectionResult(
                    id = "mock_location",
                    name = "Mock Locations",
                    category = DetectionCategory.ADB_DEBUG,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = "Mock locations are not enabled.",
                    detailedReason = "allow_mock_location=0 and no mock location app is configured.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "mock_location",
                name = "Mock Locations",
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.MEDIUM,
                description = "Could not read mock location settings.",
                detailedReason = "Settings query failed: ${e.message}",
                solution = "Check manually in Settings → Developer Options."
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
                name = "ADB over Wi-Fi Active",
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "ADB over Wi-Fi port is listening.",
                detailedReason = "Port(s) ${openPorts.joinToString(", ")} are in LISTEN state. " +
                    "Port 5555 is the ADB-over-Wi-Fi default. " +
                    "Any device on the same network can connect and issue ADB commands, " +
                    "including installing/removing apps and (on debug builds) gaining a shell.",
                solution = "Disable via 'adb disconnect' or Settings → Wireless Debugging → toggle off.",
                technicalDetail = "Listening ports: ${openPorts.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "wireless_adb",
                name = "ADB over Wi-Fi",
                category = DetectionCategory.ADB_DEBUG,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No ADB Wi-Fi ports detected as listening.",
                detailedReason = "Ports 5555/5037 are not in LISTEN state.",
                solution = "No action required."
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
                name = "BusyBox Installed",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "BusyBox binary found.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "BusyBox is a suite of Unix command-line utilities (ls, cp, wget, etc.) " +
                    "commonly installed alongside root to extend shell capabilities. " +
                    "Presence in /system/xbin or /sbin usually requires root to have been installed.",
                solution = "Remove via BusyBox uninstaller app or manually delete the binary.",
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "extra_busybox",
                name = "BusyBox",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "BusyBox not found.",
                detailedReason = "No BusyBox binary found at common locations.",
                solution = "No action required."
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
                name = "SUID su Binary Detected",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "SUID root su binary found.",
                detailedReason = "SUID binaries: ${suidFound.joinToString(", ")}. " +
                    "A SUID root su binary can be executed by any user to gain root privileges. " +
                    "This is the classic root-granting mechanism on Unix/Android.",
                solution = "Remove the su binary or revoke its SUID bit: 'chmod 755 /system/bin/su'",
                technicalDetail = "SUID su: ${suidFound.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "su_suid",
                name = "SUID su Binary",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No SUID su binary detected.",
                detailedReason = "No SUID root su binary was found at common paths.",
                solution = "No action required."
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
                name = "Detection-Bypass Module Found",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Root detection bypass module detected.",
                detailedReason = "Found: ${all.joinToString(", ")}. " +
                    "Shamiko, Zygisk-Assistant, and ReZygisk are Zygisk modules specifically designed " +
                    "to hide root from apps using DenyList / allow-listing. " +
                    "Play Integrity Fix modules spoof the Play Integrity API verdict. " +
                    "These indicate active attempts to conceal root from this app.",
                solution = "Remove hide modules from Magisk Manager → Modules.",
                technicalDetail = "Dirs: ${foundDirs.joinToString("; ")} | Pkgs: ${foundPkgs.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "shamiko_zygiskassist",
                name = "Detection-Bypass Modules",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Shamiko/ZygiskAssist detection-bypass modules found.",
                detailedReason = "No known detection-bypass module directories or packages were found.",
                solution = "No action required."
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
                    name = "Suspicious System Bind-Mounts",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "Root-framework bind-mounts over /system detected.",
                    detailedReason = "Magisk and KernelSU modules replace files in /system by " +
                        "bind-mounting modified copies from /data/adb. " +
                        "Found bind-mounts: ${suspiciousBinds.take(5).joinToString(", ")}. " +
                        "These replace stock system files with module-provided versions.",
                    solution = "Remove root modules or uninstall the root framework.",
                    technicalDetail = "Mounts: ${suspiciousBinds.take(10).joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "hidden_system_mounts",
                    name = "System Bind-Mounts",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "No suspicious /system bind-mounts found.",
                    detailedReason = "No root-framework (/data/adb) sourced bind-mounts over /system, /vendor or /product found.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "hidden_system_mounts",
                name = "System Bind-Mounts",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = "Could not read /proc/self/mountinfo.",
                detailedReason = "Failed: ${e.message}",
                solution = "Ensure /proc/self/mountinfo is accessible."
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
