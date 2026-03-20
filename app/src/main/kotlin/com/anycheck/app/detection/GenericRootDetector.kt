package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Detects APatch (another kernel-based root solution) and generic SU binaries.
 */
class GenericRootDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkAPatch(),
        checkSuBinaryPaths(),
        checkRootManagementApps(),
        checkTestKeys(),
        checkBusybox()
    )

    /** Check: APatch detection */
    private fun checkAPatch(): DetectionResult {
        val apatchFiles = listOf(
            "/data/adb/ap",
            "/data/adb/ap/bin/apd",
            "/data/adb/ap/bin/busybox",
            "/data/adb/ap/modules",
            "/data/adb/apd"
        )
        val apatchPackages = listOf(
            "me.bmax.apatch",
            "me.bmax.apatch.debug"
        )

        val foundFiles = apatchFiles.filter { File(it).exists() }
        val foundPackages = apatchPackages.filter { packageExists(it) }

        return if (foundFiles.isNotEmpty() || foundPackages.isNotEmpty()) {
            val indicators = mutableListOf<String>()
            if (foundFiles.isNotEmpty()) indicators.add("Files: ${foundFiles.joinToString(", ")}")
            if (foundPackages.isNotEmpty()) indicators.add("Packages: ${foundPackages.joinToString(", ")}")
            DetectionResult(
                id = "apatch",
                name = "APatch Detected",
                category = DetectionCategory.APATCH,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "APatch root framework detected.",
                detailedReason = "APatch is a kernel-based root solution similar to KernelSU. " +
                    "Evidence found: ${indicators.joinToString("; ")}. " +
                    "APatch patches the kernel boot image to enable root access.",
                solution = "Use APatch Manager to uninstall, then flash a stock boot image.",
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "apatch",
                name = "APatch",
                category = DetectionCategory.APATCH,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "APatch not detected.",
                detailedReason = "No APatch files or packages were found.",
                solution = "No action required."
            )
        }
    }

    /** Check: Generic su binary presence */
    private fun checkSuBinaryPaths(): DetectionResult {
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/system/sbin/su",
            "/vendor/bin/su",
            "/su/bin/su",
            "/sbin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/bin/.ext/su",
            "/system/usr/we-need-root/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/su/bin",
            "/system/xbin/daemonsu",
            "/system/app/Superuser.apk",
            "/data/data/com.noshufou.android.su",
            "/data/data/com.thirdparty.superuser",
            "/data/data/eu.chainfire.supersu"
        )
        val found = suPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "su_binary",
                name = "SU Binary Detected",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "su binary found at system locations.",
                detailedReason = "The su (superuser) binary was found at: ${found.joinToString(", ")}. " +
                    "The su binary allows apps to request elevated root privileges. " +
                    "Its presence in system paths indicates the device has been rooted.",
                solution = "Remove the su binary by booting into recovery and deleting it, " +
                    "or restore via stock system image flash.",
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "su_binary",
                name = "SU Binary",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No su binary found at common system paths.",
                detailedReason = "The su binary was not found at standard system paths.",
                solution = "No action required."
            )
        }
    }

    /** Check: Root management apps (SuperSU, SuperUser, etc.) */
    private fun checkRootManagementApps(): DetectionResult {
        val rootApps = listOf(
            "com.noshufou.android.su",          // Superuser
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",             // SuperSU
            "com.koushikdutta.superuser",       // ClockworkMod Superuser
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.kingouser.com",                // KingRoot
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",      // OneClickRoot
            "com.zhiqupk.root.global",
            "com.alephzain.framaroot",          // Framaroot
            "com.koushikdutta.rommanager",
            "com.dimonvideo.luckypatcher",      // Lucky Patcher
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.devadvance.rootcloak",         // RootCloak (root hiding)
            "com.devadvance.rootcloakplus"      // RootCloak Plus (root hiding)
        )
        val found = rootApps.filter { packageExists(it) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "root_apps",
                name = "Root Management Apps Found",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Root management or exploit apps detected.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "These apps provide root access management, exploit capabilities, " +
                    "or root-related functionality that indicates a rooted device.",
                solution = "Uninstall these apps via Settings → Apps or using adb uninstall.",
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "root_apps",
                name = "Root Management Apps",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No root management apps found.",
                detailedReason = "No known root management or exploit app packages were found.",
                solution = "No action required."
            )
        }
    }

    /** Check: Test-keys build signature */
    private fun checkTestKeys(): DetectionResult {
        val buildTags = android.os.Build.TAGS ?: ""
        val fingerprint = android.os.Build.FINGERPRINT ?: ""
        val isTestKeys = buildTags.contains("test-keys") ||
            fingerprint.contains("test-keys")
        val isDebug = buildTags.contains("debug")
        return if (isTestKeys) {
            DetectionResult(
                id = "generic_test_keys",
                name = "Test-Keys Build Detected",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Device is running a test-keys signed build.",
                detailedReason = "Build tags: '$buildTags', Fingerprint: '${fingerprint.take(60)}'. " +
                    "Test-keys builds are signed with unofficial keys, indicating a custom or rooted ROM. " +
                    "Official Google-signed builds use 'release-keys'.",
                solution = "Flash an official OEM ROM signed with release-keys via fastboot or OTA.",
                technicalDetail = "Tags: $buildTags, Fingerprint: $fingerprint"
            )
        } else if (isDebug) {
            DetectionResult(
                id = "generic_test_keys",
                name = "Debug Build Detected",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "Device is running a debug build.",
                detailedReason = "Build tags: '$buildTags'. " +
                    "Debug builds have additional debugging capabilities enabled " +
                    "and may have relaxed security restrictions.",
                solution = "Use a release/production build for better security.",
                technicalDetail = "Tags: $buildTags"
            )
        } else {
            DetectionResult(
                id = "generic_test_keys",
                name = "Build Signature",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Build appears to use official release keys.",
                detailedReason = "Build tags '$buildTags' indicate official release key signing.",
                solution = "No action required.",
                technicalDetail = "Tags: $buildTags"
            )
        }
    }

    /** Check: Busybox installation */
    private fun checkBusybox(): DetectionResult {
        val busyboxPaths = listOf(
            "/system/bin/busybox",
            "/system/xbin/busybox",
            "/sbin/busybox",
            "/data/adb/magisk/busybox",
            "/data/adb/ksu/bin/busybox",
            "/data/adb/ap/bin/busybox"
        )
        val found = busyboxPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "generic_busybox",
                name = "Busybox Found",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "Busybox binary detected.",
                detailedReason = "Busybox was found at: ${found.joinToString(", ")}. " +
                    "Busybox provides Unix utilities typically not found on Android. " +
                    "While not root itself, it is commonly installed alongside root frameworks.",
                solution = "Busybox is removed when the associated root framework is uninstalled.",
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "generic_busybox",
                name = "Busybox",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = "No Busybox binary found.",
                detailedReason = "Busybox was not found at common installation paths.",
                solution = "No action required."
            )
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
