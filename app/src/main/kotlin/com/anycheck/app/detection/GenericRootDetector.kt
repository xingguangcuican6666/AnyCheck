package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import com.anycheck.app.R
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
                name = context.getString(R.string.chk_apatch_name),
                category = DetectionCategory.APATCH,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_apatch_desc),
                detailedReason = context.getString(R.string.chk_apatch_reason, indicators.joinToString("; ")),
                solution = context.getString(R.string.chk_apatch_solution),
                technicalDetail = indicators.joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "apatch",
                name = context.getString(R.string.chk_apatch_name_nd),
                category = DetectionCategory.APATCH,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_apatch_desc_nd),
                detailedReason = context.getString(R.string.chk_apatch_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_su_binary_name),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_su_binary_desc),
                detailedReason = context.getString(R.string.chk_su_binary_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_su_binary_solution),
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "su_binary",
                name = context.getString(R.string.chk_su_binary_name_nd),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_su_binary_desc_nd),
                detailedReason = context.getString(R.string.chk_su_binary_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
            "com.devadvance.rootcloakplus",     // RootCloak Plus (root hiding)
            "moe.shizuku.privileged.api",       // Shizuku (privileged API)
            "bin.mt.plus",                      // MT Manager
            "bin.mt.termex",                    // MT Manager Terminal
            "bin.mt.plus.canary",               // MT Manager Canary
            "rikka.appops",                     // AppOps by Rikka
            "com.rosan.installer.x",            // Privileged Installer
            "cn.wq.myandroidtools"              // My Android Tools
        )
        val found = rootApps.filter { packageExists(it) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "root_apps",
                name = context.getString(R.string.chk_root_apps_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_root_apps_desc),
                detailedReason = context.getString(R.string.chk_root_apps_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_root_apps_solution),
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "root_apps",
                name = context.getString(R.string.chk_root_apps_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_root_apps_desc_nd),
                detailedReason = context.getString(R.string.chk_root_apps_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
                name = context.getString(R.string.chk_generic_test_keys_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_generic_test_keys_desc),
                detailedReason = context.getString(R.string.chk_generic_test_keys_reason, buildTags, fingerprint.take(60)),
                solution = context.getString(R.string.chk_generic_test_keys_solution),
                technicalDetail = "Tags: $buildTags, Fingerprint: $fingerprint"
            )
        } else if (isDebug) {
            DetectionResult(
                id = "generic_test_keys",
                name = context.getString(R.string.chk_generic_test_keys_name_debug),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_generic_test_keys_desc_debug),
                detailedReason = context.getString(R.string.chk_generic_test_keys_reason_debug, buildTags),
                solution = context.getString(R.string.chk_generic_test_keys_solution_debug),
                technicalDetail = "Tags: $buildTags"
            )
        } else {
            DetectionResult(
                id = "generic_test_keys",
                name = context.getString(R.string.chk_generic_test_keys_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_generic_test_keys_desc_nd),
                detailedReason = context.getString(R.string.chk_generic_test_keys_reason_nd, buildTags),
                solution = context.getString(R.string.chk_no_action_needed),
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
                name = context.getString(R.string.chk_generic_busybox_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_generic_busybox_desc),
                detailedReason = context.getString(R.string.chk_generic_busybox_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_generic_busybox_solution),
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "generic_busybox",
                name = context.getString(R.string.chk_generic_busybox_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_generic_busybox_desc_nd),
                detailedReason = context.getString(R.string.chk_generic_busybox_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
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
