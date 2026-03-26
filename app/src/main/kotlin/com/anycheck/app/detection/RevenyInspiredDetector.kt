package com.anycheck.app.detection

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Parcel
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

    companion object {
        /** Minimum user (non-system) app count below which HMA is suspected (≤ threshold = suspicious). */
        private const val HMA_MIN_APP_COUNT = 5
        /** Maximum ratio of total apps to system apps; below this HMA is suspected. */
        private const val HMA_SYSTEM_APP_RATIO_THRESHOLD = 0.03
    }

    fun runAllChecks(): List<DetectionResult> {
        val useHighTargetSdkPath = context.applicationInfo.targetSdkVersion >= 28
        val results = mutableListOf(
            checkLineageOSOrCustomROM(),
            checkCustomKernel(),
            checkResetprop(),
            checkDebugFingerprint(),
            checkHideMyApplist(),
            checkHmaBinderProbe(),
            checkHmaFilterBehavior(),
            checkHmaDataAppScan(),
            checkHMANativeDetection(),
            checkHmaColdHotTiming()
        )
        if (useHighTargetSdkPath) {
            results.add(checkDataAdbAccessForMagisk())
            results.add(checkAppListForHmaHighTargetSdk())
        } else {
            results.add(checkHmaWhitelistDetection())
            results.add(checkHmaBlacklistDetection())
        }
        results.addAll(
            listOf(
                checkMountInconsistency(),
                checkAddonDOrInstallRecovery(),
                checkSystemAppsAbsence(),
                checkVendorSepolicyLineage(),
                checkFrameworkPatch()
            )
        )
        return results
    }

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

        // Check proc/net/unix for the exact HMA socket name (full keyword, not partial "hma")
        val hasUnixSocket = runCatching {
            File("/proc/net/unix").readLines().any { line ->
                line.contains("hidemyapplist", ignoreCase = true)
            }
        }.getOrNull() ?: false

        val indicators = mutableListOf<String>()
        if (foundPackages.isNotEmpty()) indicators.add("Packages: ${foundPackages.joinToString(", ")}")
        if (hasUnixSocket) indicators.add("Unix socket matching 'hidemyapplist' in /proc/net/unix")

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
    // Check 5b: Hide My Applist — Binder probe
    //
    // HMA injects a hidden Binder service into the PackageManager Binder
    // (`android.content.pm.IPackageManager` interface).  To let its own app
    // connect to the service running inside system_server it intercepts a
    // specific custom transaction:
    //
    //   transaction code = 'H' << 24 | 'M' << 16 | 'A' << 8 | 'D'  = 0x484D4144
    //   ACTION_GET_BINDER = 1  (written as an int to the Parcel)
    //
    // On a clean device PMS does not handle this transaction and the reply
    // Parcel will contain no Binder.  If HMA is active, the reply Parcel
    // contains a valid IHMAService Binder → HMA service confirmed.
    //
    // We obtain the PM IBinder via three fallback methods to avoid relying on
    // the blocked `ServiceManager.getService()` hidden API.
    // -------------------------------------------------------------------------

    /**
     * Returns the raw IBinder for the PackageManager service using three
     * progressively less-preferred approaches, any of which may be blocked on
     * stricter Android builds.
     */
    @SuppressLint("DiscouragedPrivateApi")
    private fun getPackageManagerBinder(): android.os.IBinder? {
        // Method 1: Walk up the PackageManager class hierarchy looking for the
        // IPackageManager 'mPM' field.  'ApplicationPackageManager' has held
        // this field since Android 4 and it is still present in AOSP 14.
        try {
            val pm = context.packageManager
            var clazz: Class<*>? = pm.javaClass
            while (clazz != null) {
                try {
                    val field = clazz.getDeclaredField("mPM")
                    field.isAccessible = true
                    val ipm = field.get(pm)
                    if (ipm is android.os.IInterface) {
                        val binder = ipm.asBinder()
                        if (binder != null) return binder
                    }
                } catch (_: NoSuchFieldException) {}
                clazz = clazz.superclass
            }
        } catch (_: Exception) {}

        // Method 2: ActivityThread.currentActivityThread().getPackageManager()
        try {
            val atClass = Class.forName("android.app.ActivityThread")
            val currentThread = atClass.getMethod("currentActivityThread").invoke(null)
            val getPackageManager = atClass.getDeclaredMethod("getPackageManager")
                .also { it.isAccessible = true }
            val ipm = getPackageManager.invoke(currentThread)
            if (ipm is android.os.IInterface) {
                val binder = ipm.asBinder()
                if (binder != null) return binder
            }
        } catch (_: Exception) {}

        // Method 3: ServiceManager.getService("package") — last resort; may be
        // blocked on API 28+ by the hidden API enforcement policy.
        try {
            val smClass = Class.forName("android.os.ServiceManager")
            val binder = smClass.getMethod("getService", String::class.java)
                .invoke(null, "package") as? android.os.IBinder
            if (binder != null) return binder
        } catch (_: Exception) {}

        return null
    }

    @SuppressLint("DiscouragedPrivateApi")
    private fun checkHmaBinderProbe(): DetectionResult {
        val pmBinder = getPackageManagerBinder()
        if (pmBinder == null) {
            return DetectionResult(
                id = "reveny_hma_binder_probe",
                name = context.getString(R.string.chk_reveny_hma_binder_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_hma_binder_desc_nd),
                detailedReason = context.getString(R.string.chk_reveny_hma_binder_reason_nd),
                solution = context.getString(R.string.no_action_required),
                technicalDetail = "Unable to acquire PackageManager IBinder via any fallback method"
            )
        }

        val detected = runCatching {
            // HMAD transaction: 'H'<<24 | 'M'<<16 | 'A'<<8 | 'D' = 0x484D4144
            val transaction = 'H'.code shl 24 or ('M'.code shl 16) or ('A'.code shl 8) or 'D'.code
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                // IPackageManager descriptor + ACTION_GET_BINDER (=1)
                data.writeInterfaceToken("android.content.pm.IPackageManager")
                data.writeInt(1)
                pmBinder.transact(transaction, data, reply, 0)
                reply.readException()
                reply.readStrongBinder() != null
            } finally {
                data.recycle()
                reply.recycle()
            }
        }.getOrElse { false }

        return if (detected) {
            DetectionResult(
                id = "reveny_hma_binder_probe",
                name = context.getString(R.string.chk_reveny_hma_binder_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_hma_binder_desc),
                detailedReason = context.getString(R.string.chk_reveny_hma_binder_reason),
                solution = context.getString(R.string.chk_reveny_hma_binder_solution),
                technicalDetail = "IHMAService Binder returned from HMAD transaction (0x484D4144) on package service"
            )
        } else {
            DetectionResult(
                id = "reveny_hma_binder_probe",
                name = context.getString(R.string.chk_reveny_hma_binder_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_hma_binder_desc_nd),
                detailedReason = context.getString(R.string.chk_reveny_hma_binder_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 5c: HMA active filter-behaviour detection
    //
    // When HMA adds our app to its scope (i.e. it is actively hiding packages
    // from us), two observable anomalies arise:
    //
    //  1. Package count anomaly — the raw Binder call to
    //     IPackageManager.getInstalledPackages() with the MATCH_UNINSTALLED_PACKAGES
    //     flag (0x00002000) returns more entries than the same call made through the
    //     normal Java PackageManager API, because HMA's hook fires for the Java-API
    //     path in our process but the raw Binder bypasses the Java-level wrapper.
    //     NOTE: On modern Android the raw Binder call is ALSO intercepted by HMA
    //     (because HMA hooks system_server, not the client stub). This check
    //     therefore focuses on a different gap:
    //
    //  2. Self-visibility gap — AnyCheck's own package should ALWAYS be visible via
    //     PackageManager (HMA never hides caller == query). If
    //     `getApplicationInfo(ownPackage)` fails, something unusual is happening.
    //     More importantly: `getInstalledPackages()` on a stock device returns a
    //     count proportional to how many apps are installed. We compare the count
    //     against the number of "always-visible" packages from HMA's own
    //     `packagesShouldNotHide` list. If FEWER than all of those always-visible
    //     packages appear in the installed list, HMA is filtering aggressively.
    // -------------------------------------------------------------------------
    @SuppressLint("QueryPermissionsNeeded")
    private fun checkHmaFilterBehavior(): DetectionResult {
        // These packages are hard-coded in HMA's Constants.packagesShouldNotHide
        // and are NEVER filtered regardless of configuration.  They must always
        // appear in getInstalledPackages() on any real Android device.
        val alwaysVisiblePackages = listOf(
            "android",
            "com.android.permissioncontroller",
            "com.android.providers.settings"
        )

        val pm = context.packageManager
        val installedNames = runCatching {
            pm.getInstalledPackages(0).map { it.packageName }.toSet()
        }.getOrElse { emptySet() }

        // Count how many always-visible packages actually appeared
        val missingAlwaysVisible = alwaysVisiblePackages.filter { it !in installedNames }

        // Also attempt to read the own app info via two separate methods; any
        // discrepancy between them is a sign of active interception.
        val ownPkg = context.packageName
        val visibleViaGetAppInfo = runCatching {
            pm.getApplicationInfo(ownPkg, 0)
            true
        }.getOrElse { false }
        val visibleViaGetPkgInfo = runCatching {
            pm.getPackageInfo(ownPkg, 0)
            true
        }.getOrElse { false }
        val selfVisibilityInconsistent = visibleViaGetAppInfo != visibleViaGetPkgInfo

        // Compare getInstalledPackages vs getInstalledApplications — same filter
        // path but different AIDL methods; a significant size difference suggests
        // per-method discrepancy in the hooked PMS.
        val pkgCount = installedNames.size
        val appCount = runCatching {
            pm.getInstalledApplications(0).size
        }.getOrElse { 0 }
        val countDiscrepancy = if (pkgCount > 0 && appCount > 0) {
            Math.abs(pkgCount - appCount) > 10
        } else false

        val indicators = mutableListOf<String>()
        if (missingAlwaysVisible.isNotEmpty()) {
            indicators.add("Always-visible packages missing: ${missingAlwaysVisible.joinToString()}")
        }
        if (selfVisibilityInconsistent) {
            indicators.add("getApplicationInfo/getPackageInfo inconsistency for own package")
        }
        if (countDiscrepancy) {
            indicators.add("Package count anomaly: getInstalledPackages=$pkgCount vs getInstalledApplications=$appCount")
        }

        return if (indicators.isNotEmpty()) {
            DetectionResult(
                id = "reveny_hma_filter_behavior",
                name = context.getString(R.string.chk_reveny_hma_filter_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_hma_filter_desc),
                detailedReason = context.getString(
                    R.string.chk_reveny_hma_filter_reason,
                    indicators.joinToString("; ")
                ),
                solution = context.getString(R.string.chk_reveny_hma_filter_solution),
                technicalDetail = indicators.joinToString("\n")
            )
        } else {
            DetectionResult(
                id = "reveny_hma_filter_behavior",
                name = context.getString(R.string.chk_reveny_hma_filter_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_hma_filter_desc_nd),
                detailedReason = context.getString(R.string.chk_reveny_hma_filter_reason_nd),
                solution = context.getString(R.string.no_action_required),
                technicalDetail = "pkgCount=$pkgCount appCount=$appCount"
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 5d: HMA /data/app directory scan
    //
    // PackageManager hooks (HMA's shouldFilterApplication) prevent queries for
    // HMA's own package from returning results — but they cannot remove the APK
    // installation directory that the Android installer created in /data/app.
    //
    // We scan /data/app for directory entries whose names start with any of
    // HMA's known package name strings.  A match means HMA is physically
    // installed even if it is completely invisible to PackageManager.
    // -------------------------------------------------------------------------
    private fun checkHmaDataAppScan(): DetectionResult {
        val hmaPackages = arrayOf(
            "com.tsng.hidemyapplist",
            "com.tsng.hidemyapplist.debug",
            "cn.hidemyapplist"
        )
        val found = scanDataAppForPackages(*hmaPackages)

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "reveny_hma_data_app_scan",
                name = context.getString(R.string.chk_reveny_hma_data_app_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_hma_data_app_desc),
                detailedReason = context.getString(
                    R.string.chk_reveny_hma_data_app_reason,
                    found.joinToString("; ")
                ),
                solution = context.getString(R.string.chk_reveny_hma_data_app_solution),
                technicalDetail = found.joinToString("\n")
            )
        } else {
            DetectionResult(
                id = "reveny_hma_data_app_scan",
                name = context.getString(R.string.chk_reveny_hma_data_app_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_reveny_hma_data_app_desc_nd),
                detailedReason = context.getString(R.string.chk_reveny_hma_data_app_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 5e: HMA native detection
    //
    // Runs the native C++ HMA probe (N9) which uses raw stat(2)/opendir(3)/
    // readdir(3) and a /proc/self/maps scan to find HMA data directories,
    // miscellaneous files, and library mappings.  This cannot be intercepted
    // by HMA's own Java-layer PackageManager hook.
    // -------------------------------------------------------------------------
    private fun checkHMANativeDetection(): DetectionResult {
        val findings = NativeDetector.detectHMANative()
        return if (findings.isNotEmpty()) {
            DetectionResult(
                id = "hma_native_detect",
                name = context.getString(R.string.chk_hma_native_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hma_native_desc),
                detailedReason = context.getString(R.string.chk_hma_native_reason, findings),
                solution = context.getString(R.string.chk_hma_native_solution),
                technicalDetail = findings
            )
        } else {
            DetectionResult(
                id = "hma_native_detect",
                name = context.getString(R.string.chk_hma_native_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hma_native_desc_nd),
                detailedReason = context.getString(R.string.chk_hma_native_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 5i: HMA cold/hot startup timing analysis (SDK > 28)
    //
    // Algorithm mirrors the reference implementation in a.md:
    //
    //   Step 1 – Warm-up: issue TEST_COUNT queries for a known-present,
    //            known-not-hidden system package (com.android.settings) so that
    //            the Binder connection to PackageManagerService is fully
    //            established and the JVM/JNI paths are compiled.  Without this,
    //            the very first Binder call carries connection-setup overhead
    //            that artificially inflates fakeRatio and makes every subsequent
    //            target appear "hidden".
    //
    //   Step 2 – Per-target measurement: for EACH candidate package, measure the
    //            fake-package ratio and the target ratio back-to-back so both
    //            samples share the same Binder-warmth level.
    //
    //     Cold  = duration of the very first getPackageInfo() call (i == 0).
    //     Hot   = average duration of the remaining TEST_COUNT-1 calls.
    //     Ratio = Cold / HotAvg
    //
    // The three-way classification (from a.md):
    //
    //   R_target >> R_fake  → target benefits from PMS fast-path caching
    //                          → package is present and NOT hidden
    //   R_target ≈ R_fake   → same cold/hot profile as a non-existent package
    //                          → package truly does not exist on this device
    //   R_target  < R_fake  → cold start is abnormally short (HMA intercepts
    //                          before the full PMS lookup runs)
    //                          → package is being hidden by HMA
    //
    // Note: empirically, a non-existent package has ratio ≈ 30x (NOT ≈ 1).
    // PMS still does a full scan before returning NameNotFoundException on the
    // first call, then caches the "not found" answer for subsequent calls.
    //
    // We test Magisk, KernelSU, APatch, and HMA itself as targets.
    // Only runs on SDK > 28 (PackageManager query behaviour is stable there).
    // -------------------------------------------------------------------------
    private fun checkHmaColdHotTiming(): DetectionResult {
        if (Build.VERSION.SDK_INT <= 28) {
            return DetectionResult(
                id = "hma_cold_hot_timing",
                name = context.getString(R.string.chk_hma_cold_hot_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hma_cold_hot_desc_na),
                detailedReason = context.getString(R.string.chk_hma_cold_hot_reason_na),
                solution = context.getString(R.string.no_action_required)
            )
        }
        return try {
            val pm = context.packageManager
            val testCount = 50

            fun measureRatio(pkgName: String): Float {
                var coldTime = 0L
                var hotTotal = 0L
                for (i in 0 until testCount) {
                    val start = System.nanoTime()
                    try { pm.getPackageInfo(pkgName, 0) } catch (_: Exception) {}
                    val duration = System.nanoTime() - start
                    if (i == 0) coldTime = duration else hotTotal += duration
                }
                val hotAvg = hotTotal / (testCount - 1)
                return coldTime.toFloat() / (if (hotAvg > 0) hotAvg else 1)
            }

            // Step 1: warm up the Binder connection with a known-present,
            // known-not-hidden system package (mirrors a.md's first measurement).
            repeat(testCount) {
                try { pm.getPackageInfo("com.android.settings", 0) } catch (_: Exception) {}
            }

            data class Target(val pkg: String, val label: String, val cat: DetectionCategory)
            val targets = listOf(
                Target("com.topjohnwu.magisk",         "Magisk",            DetectionCategory.MAGISK),
                Target("com.topjohnwu.magisk.stub",    "Magisk Stub",       DetectionCategory.MAGISK),
                Target("me.weishu.kernelsu",            "KernelSU",          DetectionCategory.KERNELSU),
                Target("me.weishu.kernelsu.debug",      "KernelSU Debug",    DetectionCategory.KERNELSU),
                Target("me.bmax.apatch",                "APatch",            DetectionCategory.APATCH),
                Target("me.bmax.apatch.debug",          "APatch Debug",      DetectionCategory.APATCH),
                Target("com.tsng.hidemyapplist",        "Hide My Applist",   DetectionCategory.XPOSED),
                Target("com.tsng.hidemyapplist.debug",  "HMA Debug",         DetectionCategory.XPOSED),
                Target("cn.hidemyapplist",              "Hide My Applist CN",DetectionCategory.XPOSED)
            )

            // Step 2: for each target, measure fake then target back-to-back so
            // both samples share the same Binder-warmth level (mirrors a.md's
            // [settings → fake → target] three-step sequence per target).
            val hiddenLabels = mutableListOf<String>()
            val details = StringBuilder()
            for (t in targets) {
                val fakeRatio = measureRatio("com.random.fake.pkg.xingguang6666")
                val ratio = measureRatio(t.pkg)
                details.append("${t.label}: fakeRatio=%.2f ratio=%.2f\n".format(fakeRatio, ratio))
                if (ratio < fakeRatio) hiddenLabels.add(t.label)
            }

            if (hiddenLabels.isNotEmpty()) {
                DetectionResult(
                    id = "hma_cold_hot_timing",
                    name = context.getString(R.string.chk_hma_cold_hot_name),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_hma_cold_hot_desc),
                    detailedReason = context.getString(
                        R.string.chk_hma_cold_hot_reason, hiddenLabels.joinToString(", ")
                    ),
                    solution = context.getString(R.string.chk_hma_cold_hot_solution),
                    technicalDetail = details.toString().trimEnd()
                )
            } else {
                DetectionResult(
                    id = "hma_cold_hot_timing",
                    name = context.getString(R.string.chk_hma_cold_hot_name_nd),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_hma_cold_hot_desc_nd),
                    detailedReason = context.getString(R.string.chk_hma_cold_hot_reason_nd),
                    solution = context.getString(R.string.no_action_required),
                    technicalDetail = details.toString().trimEnd()
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "hma_cold_hot_timing",
                name = context.getString(R.string.chk_hma_cold_hot_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hma_cold_hot_desc_nd),
                detailedReason = e.message ?: "Unknown error",
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 5e: HMA whitelist detection via raw fstatat syscall (N14)
    // Probes /data/user/0/{root_manager} dirs.  EACCES means the dir exists.
    // If all root managers return ENOENT, probes system-app dirs.  If those
    // also return ENOENT via the raw syscall, HMA whitelist is masking them.
    // -------------------------------------------------------------------------
    private fun checkHmaWhitelistDetection(): DetectionResult {
        val raw = NativeDetector.detectHMAWhitelist()
        val isHmaWhitelist = raw == "hma_whitelist_detected"
        val rootManagers = if (raw.startsWith("root_managers:"))
            raw.removePrefix("root_managers:") else ""

        return when {
            isHmaWhitelist -> DetectionResult(
                id = "hma_whitelist_detect",
                name = context.getString(R.string.chk_hma_whitelist_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hma_whitelist_desc),
                detailedReason = context.getString(R.string.chk_hma_whitelist_reason),
                solution = context.getString(R.string.chk_hma_whitelist_solution),
                technicalDetail = "hma_whitelist_detected: system-app data dirs invisible via raw fstatat syscall"
            )
            rootManagers.isNotEmpty() -> DetectionResult(
                id = "hma_whitelist_detect",
                name = context.getString(R.string.chk_hma_whitelist_name_root),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hma_whitelist_desc_root),
                detailedReason = context.getString(R.string.chk_hma_whitelist_reason_root, rootManagers),
                solution = context.getString(R.string.chk_hma_whitelist_solution_root),
                technicalDetail = "root_managers via fstatat: $rootManagers"
            )
            else -> DetectionResult(
                id = "hma_whitelist_detect",
                name = context.getString(R.string.chk_hma_whitelist_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hma_whitelist_desc_nd),
                detailedReason = context.getString(R.string.chk_hma_whitelist_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 5f: HMA blacklist detection via raw fstatat syscall (N15)
    // Reads st_nlink of /data/user/0 (kernel's physical subdir count).
    // A normal device has 100+ package data dirs.  If the count is < 100,
    // HMA blacklist mode is likely hiding most installed packages from us.
    // -------------------------------------------------------------------------
    private fun checkHmaBlacklistDetection(): DetectionResult {
        val raw = NativeDetector.detectHMABlacklist()
        return if (raw.startsWith("hma_blacklist_detected")) {
            val count = raw.substringAfter("count=", "?")
            DetectionResult(
                id = "hma_blacklist_detect",
                name = context.getString(R.string.chk_hma_blacklist_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hma_blacklist_desc),
                detailedReason = context.getString(R.string.chk_hma_blacklist_reason, count),
                solution = context.getString(R.string.chk_hma_blacklist_solution),
                technicalDetail = raw
            )
        } else {
            DetectionResult(
                id = "hma_blacklist_detect",
                name = context.getString(R.string.chk_hma_blacklist_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hma_blacklist_desc_nd),
                detailedReason = context.getString(R.string.chk_hma_blacklist_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 5g: /data/adb access probe (high-targetSdk path, replaces N14/N15)
    // When targetSdkVersion >= 28 the JNI fstatat probes (N14/N15) are not
    // used.  Instead we attempt to list /data/adb via the shell.
    //   • "No such file or directory"  → directory absent, Magisk not present
    //   • "Permission denied"          → directory exists but is protected,
    //                                    strongly implies Magisk is installed
    // -------------------------------------------------------------------------
    private fun checkDataAdbAccessForMagisk(): DetectionResult {
        return try {
            // Use redirectErrorStream so both stdout and stderr are consumed from one
            // stream, eliminating any risk of a buffer-full deadlock.
            val process = ProcessBuilder("ls", "/data/adb")
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader(Charsets.UTF_8).readText()
            process.waitFor()
            process.destroy()
            when {
                output.contains("Permission denied", ignoreCase = true) ->
                    DetectionResult(
                        id = "magisk_data_adb_access",
                        name = context.getString(R.string.chk_data_adb_magisk_name),
                        category = DetectionCategory.MAGISK,
                        status = DetectionStatus.DETECTED,
                        riskLevel = RiskLevel.CRITICAL,
                        description = context.getString(R.string.chk_data_adb_magisk_desc),
                        detailedReason = context.getString(R.string.chk_data_adb_magisk_reason),
                        solution = context.getString(R.string.chk_magisk_files_solution),
                        technicalDetail = "ls /data/adb: $output"
                    )
                else ->
                    DetectionResult(
                        id = "magisk_data_adb_access",
                        name = context.getString(R.string.chk_data_adb_magisk_name_nd),
                        category = DetectionCategory.MAGISK,
                        status = DetectionStatus.NOT_DETECTED,
                        riskLevel = RiskLevel.CRITICAL,
                        description = context.getString(R.string.chk_data_adb_magisk_desc_nd),
                        detailedReason = context.getString(R.string.chk_data_adb_magisk_reason_nd),
                        solution = context.getString(R.string.no_action_required)
                    )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "magisk_data_adb_access",
                name = context.getString(R.string.chk_data_adb_magisk_name_nd),
                category = DetectionCategory.MAGISK,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_data_adb_magisk_desc_nd),
                detailedReason = e.message ?: "Unknown error",
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 5h: app-list size probe for HMA (high-targetSdk path)
    // When targetSdkVersion >= 28, replaces the JNI blacklist/whitelist checks.
    // HMA typically hides *user-installed* (non-system) apps while leaving
    // system apps visible.  We therefore compare the non-system app count
    // against the threshold, not the total count.
    //   • userAppCount ≤ 5, OR
    //   • userAppCount < 3 % of the number of system apps
    // …then HMA (or an equivalent framework) is very likely hiding most of the
    // installed package list from this app.
    // -------------------------------------------------------------------------
    private fun checkAppListForHmaHighTargetSdk(): DetectionResult {
        return try {
            val pm = context.packageManager
            val allApps = pm.getInstalledApplications(0)
            val totalCount = allApps.size
            val systemCount = allApps.count {
                it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0
            }
            // Non-system (user-installed) apps are what HMA typically hides.
            val userAppCount = totalCount - systemCount
            val suspicious = userAppCount <= HMA_MIN_APP_COUNT ||
                (systemCount > 0 && userAppCount < systemCount * HMA_SYSTEM_APP_RATIO_THRESHOLD)
            if (suspicious) {
                DetectionResult(
                    id = "hma_app_list_small",
                    name = context.getString(R.string.chk_hma_app_list_name),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_hma_app_list_desc),
                    detailedReason = context.getString(
                        R.string.chk_hma_app_list_reason, userAppCount, systemCount
                    ),
                    solution = context.getString(R.string.chk_hma_whitelist_solution),
                    technicalDetail = "userApps=$userAppCount systemApps=$systemCount totalApps=$totalCount"
                )
            } else {
                DetectionResult(
                    id = "hma_app_list_small",
                    name = context.getString(R.string.chk_hma_app_list_name_nd),
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_hma_app_list_desc_nd),
                    detailedReason = context.getString(
                        R.string.chk_hma_app_list_reason_nd, userAppCount, systemCount
                    ),
                    solution = context.getString(R.string.no_action_required)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "hma_app_list_small",
                name = context.getString(R.string.chk_hma_app_list_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hma_app_list_desc_nd),
                detailedReason = e.message ?: "Unknown error",
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Scans /data/app for installed package directories matching any of the
     * given package name prefixes.  This bypasses PackageManager hooks (e.g.
     * HMA's shouldFilterApplication) because we read the file-system directly.
     *
     * Android 9+ layout:  /data/app/~~RANDOM==/PACKAGE-RANDOM==/base.apk
     * Android 7–8 layout: /data/app/PACKAGE-N/base.apk
     *
     * Returns a list of matching install-directory paths.
     */
    private fun scanDataAppForPackages(vararg packages: String): List<String> {
        val found = mutableListOf<String>()
        try {
            val dataApp = File("/data/app")
            val outerEntries = dataApp.listFiles() ?: return found
            for (outer in outerEntries) {
                if (!outer.isDirectory) continue
                val outerName = outer.name
                // Android 7–8 flat layout: entry is directly the package install dir
                for (pkg in packages) {
                    if (outerName == pkg || outerName.startsWith("$pkg-")) {
                        found.add(outer.path)
                    }
                }
                // Android 9+ double-encoded layout: outer dir is ~~RANDOM==
                if (outerName.startsWith("~~")) {
                    try {
                        val innerEntries = outer.listFiles() ?: continue
                        for (inner in innerEntries) {
                            if (!inner.isDirectory) continue
                            for (pkg in packages) {
                                if (inner.name == pkg || inner.name.startsWith("$pkg-")) {
                                    found.add(inner.path)
                                }
                            }
                        }
                    } catch (_: Exception) {}
                }
            }
        } catch (_: Exception) {}
        return found
    }

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
