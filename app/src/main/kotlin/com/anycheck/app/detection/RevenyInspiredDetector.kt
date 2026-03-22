package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.anycheck.app.R
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.io.InputStreamReader

/**
 * Detection techniques inspired by reveny/Android-Native-Root-Detector.
 * Covers: custom ROM/kernel fingerprinting, resetprop, Hide My Applist,
 * mount inconsistency, addon.d persistence, system-app absence, vendor
 * sepolicy patching, and framework patching indicators.
 */
class RevenyInspiredDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkLineageOSOrCustomROM(),
        checkCustomKernel(),
        checkResetprop(),
        checkDebugFingerprint(),
        checkHideMyApplist(),
        checkMountInconsistency(),
        checkAddonDOrInstallRecovery(),
        checkSystemAppsAbsence(),
        checkVendorSepolicyLineage(),
        checkFrameworkPatch()
    )

    // -------------------------------------------------------------------------
    // Check 1: LineageOS / Custom ROM
    // Mirrors reveny "Detected LineageOS" and "Detected Custom ROM"
    // -------------------------------------------------------------------------
    private fun checkLineageOSOrCustomROM(): DetectionResult {
        val lineageProps = listOf(
            "ro.lineage.version",
            "ro.lineageos.version",
            "ro.cm.version",
            "ro.cyanogenmod.version",
            "ro.pixel.version"
        )
        val detectedProps = lineageProps.filter { readProp(it) != null }

        // Also inspect build fingerprint and display for common custom ROM strings
        val fingerprint = Build.FINGERPRINT ?: ""
        val display = Build.DISPLAY ?: ""
        val brand = Build.BRAND ?: ""
        val customRomKeywords = listOf("lineage", "cyanogenmod", "resurrection", "paranoid",
            "calyx", "graphene", "e/os", "calyxos", "havoc", "pixel_experience",
            "evolution_x", "arrow", "dot", "aosip", "carbon", "slim", "aicp",
            "omni", "validus", "bliss", "rebellion", "nusantara", "ion", "rising")
        val matchedKeywords = customRomKeywords.filter { kw ->
            fingerprint.contains(kw, ignoreCase = true) ||
                display.contains(kw, ignoreCase = true) ||
                brand.contains(kw, ignoreCase = true)
        }

        val vendorSepolicyFile = File("/vendor/etc/selinux/vendor_sepolicy.cil")
        val hasLineageSepolicy = vendorSepolicyFile.exists() && runCatching {
            vendorSepolicyFile.readText(Charsets.UTF_8)
        }.getOrNull()?.contains("lineage", ignoreCase = true) == true

        val indicators = mutableListOf<String>()
        if (detectedProps.isNotEmpty()) indicators.add("Props: ${detectedProps.joinToString(", ")}")
        if (matchedKeywords.isNotEmpty()) {
            indicators.add("Fingerprint/display keywords: ${matchedKeywords.joinToString(", ")}")
        }
        if (hasLineageSepolicy) indicators.add("vendor_sepolicy.cil contains 'lineage'")

        return if (indicators.isNotEmpty()) {
            DetectionResult(
                id = "reveny_custom_rom",
                name = context.getString(R.string.chk_reveny_custom_rom_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_custom_rom_desc),
                detailedReason = context.getString(R.string.chk_reveny_custom_rom_reason, indicators.joinToString("; ")),
                solution = context.getString(R.string.chk_reveny_custom_rom_solution),
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "reveny_custom_rom",
                name = context.getString(R.string.chk_reveny_custom_rom_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_custom_rom_desc_nd),
                detailedReason = context.getString(R.string.chk_reveny_custom_rom_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 2: Custom / non-stock kernel
    // Mirrors reveny "Detected Custom Kernel"
    // -------------------------------------------------------------------------
    private fun checkCustomKernel(): DetectionResult {
        val kernelVersion = readProp("os.version")
            ?: runCatching { System.getProperty("os.version") }.getOrNull()
            ?: ""
        // /proc/version gives the full kernel banner
        val procVersion = runCatching {
            File("/proc/version").readText(Charsets.UTF_8).trim()
        }.getOrNull() ?: ""

        // Custom kernel indicators: common kernel project names / unofficial strings
        val customKernelKeywords = listOf(
            "lineageos", "lineage", "kali", "nethunter", "elementary",
            "sultan", "arter97", "flar2", "blu_spark", "eas", "optimus",
            "ElementalX", "liqx", "savoca", "neffos", "sunxi-kernel",
            "franco", "zen", "CAF"
        )
        val matched = customKernelKeywords.filter { kw ->
            procVersion.contains(kw, ignoreCase = true)
        }

        // Also check if kernel was compiled with a non-OEM email/hostname
        val customCompilerPattern = Regex("""@[a-z0-9\-]+\.(local|home|pc|laptop|desktop|server)""",
            RegexOption.IGNORE_CASE)
        val hasPersonalBuild = customCompilerPattern.containsMatchIn(procVersion)

        val indicators = mutableListOf<String>()
        if (matched.isNotEmpty()) indicators.add("Keywords: ${matched.joinToString(", ")}")
        if (hasPersonalBuild) indicators.add("Personal build hostname in kernel banner")

        return if (indicators.isNotEmpty()) {
            DetectionResult(
                id = "reveny_custom_kernel",
                name = context.getString(R.string.chk_reveny_custom_kernel_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_reveny_custom_kernel_desc),
                detailedReason = context.getString(R.string.chk_reveny_custom_kernel_reason, indicators.joinToString("; ")),
                solution = context.getString(R.string.chk_reveny_custom_kernel_solution),
                technicalDetail = "Kernel banner: ${procVersion.take(200)}"
            )
        } else {
            DetectionResult(
                id = "reveny_custom_kernel",
                name = context.getString(R.string.chk_reveny_custom_kernel_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_reveny_custom_kernel_desc_nd),
                detailedReason = context.getString(R.string.chk_reveny_custom_kernel_reason_nd),
                solution = context.getString(R.string.no_action_required),
                technicalDetail = "Kernel banner: ${procVersion.take(200)}"
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 3: Resetprop binary
    // Mirrors reveny "Detected Resetprop"
    // resetprop is a Magisk-bundled tool for faking system properties.
    // -------------------------------------------------------------------------
    private fun checkResetprop(): DetectionResult {
        val paths = listOf(
            "/data/adb/magisk/resetprop",
            "/data/adb/modules/.core/resetprop",
            "/sbin/resetprop",
            "/system/bin/resetprop",
            "/system/xbin/resetprop"
        )
        val found = paths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "reveny_resetprop",
                name = context.getString(R.string.chk_reveny_resetprop_name),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_resetprop_desc),
                detailedReason = context.getString(R.string.chk_reveny_resetprop_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_reveny_resetprop_solution),
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "reveny_resetprop",
                name = context.getString(R.string.chk_reveny_resetprop_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_resetprop_desc_nd),
                detailedReason = context.getString(R.string.chk_reveny_resetprop_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 4: Debug fingerprint / userdebug build
    // Mirrors reveny "Debug Fingerprint detected"
    // -------------------------------------------------------------------------
    private fun checkDebugFingerprint(): DetectionResult {
        val fingerprint = Build.FINGERPRINT ?: ""
        val buildType = Build.TYPE ?: ""
        val tags = Build.TAGS ?: ""

        val isUserDebug = buildType.equals("userdebug", ignoreCase = true)
        val isEng = buildType.equals("eng", ignoreCase = true)
        val fingerprintHasDebug = fingerprint.contains(":userdebug/") ||
            fingerprint.contains(":eng/")

        return if (isUserDebug || isEng || fingerprintHasDebug) {
            val detail = "buildType=$buildType, fingerprint=${fingerprint.take(80)}, tags=$tags"
            DetectionResult(
                id = "reveny_debug_fingerprint",
                name = context.getString(R.string.chk_reveny_debug_fp_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_debug_fp_desc),
                detailedReason = context.getString(R.string.chk_reveny_debug_fp_reason, buildType, fingerprint.take(80)),
                solution = context.getString(R.string.chk_reveny_debug_fp_solution),
                technicalDetail = detail
            )
        } else {
            DetectionResult(
                id = "reveny_debug_fingerprint",
                name = context.getString(R.string.chk_reveny_debug_fp_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_debug_fp_desc_nd),
                detailedReason = context.getString(R.string.chk_reveny_debug_fp_reason_nd, buildType),
                solution = context.getString(R.string.no_action_required),
                technicalDetail = "buildType=$buildType"
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 5: Hide My Applist
    // Mirrors reveny "Detected Hide My Applist"
    // -------------------------------------------------------------------------
    private fun checkHideMyApplist(): DetectionResult {
        val hmaPackages = listOf(
            "com.tsng.hidemyapplist",
            "com.tsng.hidemyapplist.debug",
            "cn.hidemyapplist"
        )
        val foundPackages = hmaPackages.filter { packageExists(it) }

        // Also check for service socket that HMA creates
        val socketPath = "/dev/unix/hidemyapplist"
        val hasSocket = File(socketPath).exists()

        // Check proc/net/unix for HMA socket name
        val hasUnixSocket = runCatching {
            File("/proc/net/unix").readLines().any { line ->
                line.contains("hidemyapplist", ignoreCase = true) ||
                    line.contains("hma", ignoreCase = true)
            }
        }.getOrNull() ?: false

        val indicators = mutableListOf<String>()
        if (foundPackages.isNotEmpty()) indicators.add("Packages: ${foundPackages.joinToString(", ")}")
        if (hasSocket) indicators.add("Socket: $socketPath")
        if (hasUnixSocket) indicators.add("Unix socket in /proc/net/unix")

        return if (indicators.isNotEmpty()) {
            DetectionResult(
                id = "reveny_hide_my_applist",
                name = context.getString(R.string.chk_reveny_hma_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_hma_desc),
                detailedReason = context.getString(R.string.chk_reveny_hma_reason, indicators.joinToString("; ")),
                solution = context.getString(R.string.chk_reveny_hma_solution),
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "reveny_hide_my_applist",
                name = context.getString(R.string.chk_reveny_hma_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_hma_desc_nd),
                detailedReason = context.getString(R.string.chk_reveny_hma_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 6: Mount inconsistency / umount-based hiding
    // Mirrors reveny "Detected Mount Inconsistency" and "Umount Detected"
    // Compares /proc/mounts with /proc/self/mountinfo to find hidden mounts.
    // -------------------------------------------------------------------------
    private fun checkMountInconsistency(): DetectionResult {
        return try {
            val mountsEntries = File("/proc/mounts").readLines()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .map { it.split("\\s+".toRegex()).getOrElse(1) { "" } } // target/mountpoint
                .toSet()

            val mountInfoEntries = File("/proc/self/mountinfo").readLines()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .map { parts ->
                    // mountinfo field 5 is the mount point
                    parts.split("\\s+".toRegex()).getOrElse(4) { "" }
                }
                .toSet()

            // Entries in mountinfo but not in mounts could indicate umount hiding
            val hiddenMounts = mountInfoEntries - mountsEntries
            // Filter to only suspicious paths (root-related targets)
            val suspiciousPaths = listOf("/system", "/vendor", "/product", "/apex",
                "/data", "/sbin", "/proc")
            val suspicious = hiddenMounts.filter { mp ->
                suspiciousPaths.any { mp.startsWith(it) }
            }

            if (suspicious.isNotEmpty()) {
                DetectionResult(
                    id = "reveny_mount_inconsistency",
                    name = context.getString(R.string.chk_reveny_mount_inc_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_reveny_mount_inc_desc),
                    detailedReason = context.getString(R.string.chk_reveny_mount_inc_reason, suspicious.take(5).joinToString(", ")),
                    solution = context.getString(R.string.chk_reveny_mount_inc_solution),
                    technicalDetail = "Hidden mount points: ${suspicious.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "reveny_mount_inconsistency",
                    name = context.getString(R.string.chk_reveny_mount_inc_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_reveny_mount_inc_desc_nd),
                    detailedReason = context.getString(R.string.chk_reveny_mount_inc_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (_: Exception) {
            DetectionResult(
                id = "reveny_mount_inconsistency",
                name = context.getString(R.string.chk_reveny_mount_inc_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_mount_inc_desc_error),
                detailedReason = context.getString(R.string.chk_reveny_mount_inc_reason_error),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 7: Addon.d or install-recovery.sh
    // Mirrors reveny "Addon.d or install-recovery.sh exists"
    // These scripts are used by custom ROMs / Magisk to persist across OTA updates.
    // -------------------------------------------------------------------------
    private fun checkAddonDOrInstallRecovery(): DetectionResult {
        val addonDDir = File("/system/addon.d")
        val installRecovery = File("/system/etc/install-recovery.sh")
        val installRecovery2 = File("/system/bin/install-recovery.sh")

        val hasAddonD = addonDDir.exists() && (addonDDir.list()?.isNotEmpty() == true)
        val hasInstallRecovery = installRecovery.exists() || installRecovery2.exists()

        val indicators = mutableListOf<String>()
        if (hasAddonD) {
            val scripts = addonDDir.list() ?: emptyArray()
            indicators.add("addon.d directory with ${scripts.size} script(s): ${scripts.take(3).joinToString(", ")}")
        }
        if (hasInstallRecovery) indicators.add("install-recovery.sh present")

        return if (indicators.isNotEmpty()) {
            DetectionResult(
                id = "reveny_addon_d",
                name = context.getString(R.string.chk_reveny_addon_d_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_reveny_addon_d_desc),
                detailedReason = context.getString(R.string.chk_reveny_addon_d_reason, indicators.joinToString("; ")),
                solution = context.getString(R.string.chk_reveny_addon_d_solution),
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "reveny_addon_d",
                name = context.getString(R.string.chk_reveny_addon_d_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_reveny_addon_d_desc_nd),
                detailedReason = context.getString(R.string.chk_reveny_addon_d_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 8: System apps absence
    // Mirrors reveny "No system apps found"
    // If the PackageManager returns very few system apps, an app-list hiding
    // framework (e.g. HMA) is likely intercepting the call.
    // -------------------------------------------------------------------------
    private fun checkSystemAppsAbsence(): DetectionResult {
        return try {
            val pm = context.packageManager
            val systemApps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0 }

            // A typical Android device has 50–200+ system apps. Fewer than 5 is extremely suspicious.
            val threshold = 5
            return if (systemApps.size < threshold) {
                DetectionResult(
                    id = "reveny_system_apps_absent",
                    name = context.getString(R.string.chk_reveny_sys_apps_name),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_reveny_sys_apps_desc),
                    detailedReason = context.getString(R.string.chk_reveny_sys_apps_reason, systemApps.size),
                    solution = context.getString(R.string.chk_reveny_sys_apps_solution),
                    technicalDetail = "System app count: ${systemApps.size}"
                )
            } else {
                DetectionResult(
                    id = "reveny_system_apps_absent",
                    name = context.getString(R.string.chk_reveny_sys_apps_name_nd),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_reveny_sys_apps_desc_nd),
                    detailedReason = context.getString(R.string.chk_reveny_sys_apps_reason_nd, systemApps.size),
                    solution = context.getString(R.string.no_action_required),
                    technicalDetail = "System app count: ${systemApps.size}"
                )
            }
        } catch (_: Exception) {
            DetectionResult(
                id = "reveny_system_apps_absent",
                name = context.getString(R.string.chk_reveny_sys_apps_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_sys_apps_desc_error),
                detailedReason = context.getString(R.string.chk_reveny_sys_apps_reason_error),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 9: vendor_sepolicy.cil contains LineageOS entries
    // Mirrors reveny "vendor_sepolicy.cil contains lineage"
    // -------------------------------------------------------------------------
    private fun checkVendorSepolicyLineage(): DetectionResult {
        val sepolicyFile = File("/vendor/etc/selinux/vendor_sepolicy.cil")
        if (!sepolicyFile.exists()) {
            return DetectionResult(
                id = "reveny_vendor_sepolicy",
                name = context.getString(R.string.chk_reveny_vendor_sep_name_notfound),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_reveny_vendor_sep_desc_notfound),
                detailedReason = context.getString(R.string.chk_reveny_vendor_sep_reason_notfound),
                solution = context.getString(R.string.no_action_required)
            )
        }
        return try {
            val content = sepolicyFile.readText(Charsets.UTF_8)
            val lineageEntries = listOf("lineage", "lineageos", "cyanogenmod")
            val found = lineageEntries.filter { content.contains(it, ignoreCase = true) }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "reveny_vendor_sepolicy",
                    name = context.getString(R.string.chk_reveny_vendor_sep_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_reveny_vendor_sep_desc),
                    detailedReason = context.getString(R.string.chk_reveny_vendor_sep_reason, found.joinToString(", ")),
                    solution = context.getString(R.string.chk_reveny_vendor_sep_solution),
                    technicalDetail = "Found keywords: ${found.joinToString(", ")} in vendor_sepolicy.cil"
                )
            } else {
                DetectionResult(
                    id = "reveny_vendor_sepolicy",
                    name = context.getString(R.string.chk_reveny_vendor_sep_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_reveny_vendor_sep_desc_nd),
                    detailedReason = context.getString(R.string.chk_reveny_vendor_sep_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (_: Exception) {
            DetectionResult(
                id = "reveny_vendor_sepolicy",
                name = context.getString(R.string.chk_reveny_vendor_sep_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_reveny_vendor_sep_desc_error),
                detailedReason = context.getString(R.string.chk_reveny_vendor_sep_reason_error),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 10: Framework patch indicators
    // Mirrors reveny "Detected Framework Patch"
    // LSPosed and some Zygisk modules patch /system/framework/*.jar (or .odex)
    // We look for anomalous modification times compared to other framework files.
    // -------------------------------------------------------------------------
    private fun checkFrameworkPatch(): DetectionResult {
        val frameworkDir = File("/system/framework")
        if (!frameworkDir.exists()) {
            return DetectionResult(
                id = "reveny_framework_patch",
                name = context.getString(R.string.chk_reveny_fw_patch_name_noaccess),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_fw_patch_desc_noaccess),
                detailedReason = context.getString(R.string.chk_reveny_fw_patch_reason_noaccess),
                solution = context.getString(R.string.no_action_required)
            )
        }
        return try {
            val frameworkFiles = frameworkDir.listFiles() ?: emptyArray()
            if (frameworkFiles.isEmpty()) {
                return DetectionResult(
                    id = "reveny_framework_patch",
                    name = context.getString(R.string.chk_reveny_fw_patch_name_noaccess),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_reveny_fw_patch_desc_empty),
                    detailedReason = context.getString(R.string.chk_reveny_fw_patch_reason_empty),
                    solution = context.getString(R.string.no_action_required)
                )
            }

            // Check for known LSPosed / Xposed framework injection files
            val suspiciousNames = listOf(
                "XposedBridge.jar",
                "xposed",
                "lspd",
                "edxp",
                "framework-patch"
            )
            val suspiciousFound = frameworkFiles
                .filter { f -> suspiciousNames.any { f.name.contains(it, ignoreCase = true) } }
                .map { it.name }

            // Check modification time anomaly: services.jar / services.odex modified
            // significantly more recently than other framework files is suspicious.
            val servicesJar = frameworkFiles.firstOrNull { it.name == "services.jar" }
            val servicesOdex = frameworkDir.walkTopDown()
                .firstOrNull { it.name == "services.odex" }
            val otherFiles = frameworkFiles.filter {
                it.name != "services.jar" && it.isFile && it.length() > 0
            }

            val anomalousModTime = if (servicesJar != null && otherFiles.isNotEmpty()) {
                val servicesTime = servicesJar.lastModified()
                val medianTime = otherFiles.map { it.lastModified() }.sorted()
                    .let { times -> times[times.size / 2] }
                // If services.jar is >30 days newer than median, flag it
                val diffDays = (servicesTime - medianTime) / (1000L * 60 * 60 * 24)
                diffDays > 30
            } else false

            val indicators = mutableListOf<String>()
            if (suspiciousFound.isNotEmpty()) indicators.add("Suspicious files: ${suspiciousFound.joinToString(", ")}")
            if (anomalousModTime) indicators.add("services.jar modification time anomaly detected")

            if (indicators.isNotEmpty()) {
                DetectionResult(
                    id = "reveny_framework_patch",
                    name = context.getString(R.string.chk_reveny_fw_patch_name),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_reveny_fw_patch_desc),
                    detailedReason = context.getString(R.string.chk_reveny_fw_patch_reason, indicators.joinToString("; ")),
                    solution = context.getString(R.string.chk_reveny_fw_patch_solution),
                    technicalDetail = indicators.joinToString("; ")
                )
            } else {
                DetectionResult(
                    id = "reveny_framework_patch",
                    name = context.getString(R.string.chk_reveny_fw_patch_name_nd),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_reveny_fw_patch_desc_nd),
                    detailedReason = context.getString(R.string.chk_reveny_fw_patch_reason_nd),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (_: Exception) {
            DetectionResult(
                id = "reveny_framework_patch",
                name = context.getString(R.string.chk_reveny_fw_patch_name_noaccess),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_fw_patch_desc_error),
                detailedReason = context.getString(R.string.chk_reveny_fw_patch_reason_error),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------
    private fun readProp(key: String): String? {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
            val result = BufferedReader(InputStreamReader(process.inputStream))
                .readLine()?.trim()
            process.destroy()
            if (result.isNullOrEmpty()) null else result
        } catch (_: Exception) {
            null
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
