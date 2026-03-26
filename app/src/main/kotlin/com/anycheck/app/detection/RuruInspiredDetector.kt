package com.anycheck.app.detection

import android.accounts.AccountManager
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import com.anycheck.app.R
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.NetworkInterface
import java.nio.charset.StandardCharsets

/**
 * Detection techniques inspired by byxiaorun/Ruru (ApplistDetector).
 *
 * Covers checks unique to Ruru that are not already present in other AnyCheck detectors:
 *  1. Dual / Work-profile environment detection
 *  2. XPrivacyLua data directory
 *  3. Xposed Edge data directory
 *  4. Riru Clipboard data directory
 *  5. Privacy Space (cn.geektang.privacyspace) data directory
 *  6. Hide My Applist old-version data directory
 *  7. PM cross-method anomaly  (shell `pm list packages` vs. API)
 *  8. Xposed module metadata scan (xposedminversion / xposeddescription)
 *  9. LSPatch via appComponentFactory (API 28+)
 * 10. Account list anomaly
 * 11. VPN connection (tun0 / ppp0 / http.proxyHost)
 * 12. Accessibility services scan
 * 13. Package-manager API discrepancy (getPackageUid / getInstallSourceInfo / getLaunchIntentForPackage)
 */
class RuruInspiredDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkDualOrWorkProfile(),
        checkXPrivacyLuaFile(),
        checkXposedEdgeFile(),
        checkRiruClipboardFile(),
        checkPrivacySpaceFile(),
        checkHmaOldVersionFile(),
        checkHmaCurrentDataDir(),
        checkPmCommandVsApi(),
        checkXposedModuleMetadata(),
        checkLSPatchAppComponentFactory(),
        checkAccountListAnomaly(),
        checkVpnConnection(),
        checkAccessibilityServices(),
        checkPmApiDiscrepancy()
    )

    // -------------------------------------------------------------------------
    // 1. Dual / Work-profile detection
    // Ruru: filesDir starts with /data/user but NOT /data/user/0
    // -------------------------------------------------------------------------
    private fun checkDualOrWorkProfile(): DetectionResult {
        val filesDir = context.filesDir.path
        val isDual = filesDir.startsWith("/data/user") && !filesDir.startsWith("/data/user/0")
        return if (isDual) {
            DetectionResult(
                id = "ruru_dual_work_profile",
                name = context.getString(R.string.chk_ruru_dual_profile_name),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ruru_dual_profile_desc),
                detailedReason = context.getString(R.string.chk_ruru_dual_profile_reason, filesDir),
                solution = context.getString(R.string.chk_ruru_dual_profile_solution),
                technicalDetail = "filesDir=$filesDir"
            )
        } else {
            DetectionResult(
                id = "ruru_dual_work_profile",
                name = context.getString(R.string.chk_ruru_dual_profile_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ruru_dual_profile_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_dual_profile_reason_nd, filesDir),
                solution = context.getString(R.string.no_action_required),
                technicalDetail = "filesDir=$filesDir"
            )
        }
    }

    // -------------------------------------------------------------------------
    // 2. XPrivacyLua data directory
    // Ruru: detectFile("/data/system/xlua")
    // -------------------------------------------------------------------------
    private fun checkXPrivacyLuaFile(): DetectionResult {
        val path = "/data/system/xlua"
        val exists = File(path).exists()
        return if (exists) {
            DetectionResult(
                id = "ruru_xprivacylua_file",
                name = context.getString(R.string.chk_ruru_xprivacy_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_xprivacy_desc),
                detailedReason = context.getString(R.string.chk_ruru_xprivacy_reason),
                solution = context.getString(R.string.chk_ruru_xprivacy_solution),
                technicalDetail = "Path exists: $path"
            )
        } else {
            DetectionResult(
                id = "ruru_xprivacylua_file",
                name = context.getString(R.string.chk_ruru_xprivacy_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_xprivacy_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_xprivacy_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 3. Xposed Edge data directory
    // Ruru: detectFile("/data/system/xedge")
    // -------------------------------------------------------------------------
    private fun checkXposedEdgeFile(): DetectionResult {
        val path = "/data/system/xedge"
        val exists = File(path).exists()
        return if (exists) {
            DetectionResult(
                id = "ruru_xposed_edge_file",
                name = context.getString(R.string.chk_ruru_xedge_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ruru_xedge_desc),
                detailedReason = context.getString(R.string.chk_ruru_xedge_reason),
                solution = context.getString(R.string.chk_ruru_xedge_solution),
                technicalDetail = "Path exists: $path"
            )
        } else {
            DetectionResult(
                id = "ruru_xposed_edge_file",
                name = context.getString(R.string.chk_ruru_xedge_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ruru_xedge_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_xedge_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 4. Riru Clipboard data directory
    // Ruru: detectFile("/data/misc/clipboard")
    // -------------------------------------------------------------------------
    private fun checkRiruClipboardFile(): DetectionResult {
        val path = "/data/misc/clipboard"
        val exists = File(path).exists()
        return if (exists) {
            DetectionResult(
                id = "ruru_riru_clipboard_file",
                name = context.getString(R.string.chk_ruru_riru_clip_name),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ruru_riru_clip_desc),
                detailedReason = context.getString(R.string.chk_ruru_riru_clip_reason),
                solution = context.getString(R.string.chk_ruru_riru_clip_solution),
                technicalDetail = "Path exists: $path"
            )
        } else {
            DetectionResult(
                id = "ruru_riru_clipboard_file",
                name = context.getString(R.string.chk_ruru_riru_clip_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ruru_riru_clip_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_riru_clip_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 5. Privacy Space data directory
    // Ruru: detectFile("/data/system/cn.geektang.privacyspace")
    // -------------------------------------------------------------------------
    private fun checkPrivacySpaceFile(): DetectionResult {
        val path = "/data/system/cn.geektang.privacyspace"
        val exists = File(path).exists()
        return if (exists) {
            DetectionResult(
                id = "ruru_privacy_space_file",
                name = context.getString(R.string.chk_ruru_privacy_space_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_privacy_space_desc),
                detailedReason = context.getString(R.string.chk_ruru_privacy_space_reason),
                solution = context.getString(R.string.chk_ruru_privacy_space_solution),
                technicalDetail = "Path exists: $path"
            )
        } else {
            DetectionResult(
                id = "ruru_privacy_space_file",
                name = context.getString(R.string.chk_ruru_privacy_space_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_privacy_space_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_privacy_space_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 6. HMA old-version data directory
    // Ruru: detectFile("/data/misc/hide_my_applist")
    // -------------------------------------------------------------------------
    private fun checkHmaOldVersionFile(): DetectionResult {
        val path = "/data/misc/hide_my_applist"
        val exists = File(path).exists()
        return if (exists) {
            DetectionResult(
                id = "ruru_hma_old_file",
                name = context.getString(R.string.chk_ruru_hma_old_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_hma_old_desc),
                detailedReason = context.getString(R.string.chk_ruru_hma_old_reason),
                solution = context.getString(R.string.chk_ruru_hma_old_solution),
                technicalDetail = "Path exists: $path"
            )
        } else {
            DetectionResult(
                id = "ruru_hma_old_file",
                name = context.getString(R.string.chk_ruru_hma_old_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_hma_old_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_hma_old_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 6b. HMA current-version data directory (random-suffix)
    // HMA v3+ creates /data/misc/hide_my_applist_{random_16_chars} and stores
    // its config, logs, and filter_count inside it.  This check scans
    // /data/misc/ for any entry beginning with "hide_my_applist_" and, for
    // each match, checks for the known artifact files that HMA itself creates.
    // -------------------------------------------------------------------------
    private fun checkHmaCurrentDataDir(): DetectionResult {
        val indicators = mutableListOf<String>()
        try {
            val miscDir = File("/data/misc")
            val hmaEntries = miscDir.listFiles { f ->
                f.name.startsWith("hide_my_applist_")
            } ?: emptyArray()

            for (entry in hmaEntries) {
                val info = buildString {
                    append(entry.path)
                    // Look for well-known HMA artifacts inside each directory.
                    val artifacts = listOf("config.json", "filter_count", "log/runtime.log", "log/old.log")
                    val found = artifacts.filter { File(entry, it).exists() }
                    if (found.isNotEmpty()) append(" [${found.joinToString()}]")
                }
                indicators.add(info)
            }
        } catch (_: Exception) {}

        return if (indicators.isNotEmpty()) {
            DetectionResult(
                id = "ruru_hma_current_dir",
                name = context.getString(R.string.chk_ruru_hma_dir_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_hma_dir_desc),
                detailedReason = context.getString(
                    R.string.chk_ruru_hma_dir_reason,
                    indicators.joinToString("; ")
                ),
                solution = context.getString(R.string.chk_ruru_hma_dir_solution),
                technicalDetail = indicators.joinToString("\n")
            )
        } else {
            DetectionResult(
                id = "ruru_hma_current_dir",
                name = context.getString(R.string.chk_ruru_hma_dir_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_hma_dir_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_hma_dir_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 7. PM cross-method anomaly
    // Ruru: compares `pm list packages` shell output against getInstalledPackages()
    // A discrepancy means something is intercepting PackageManager calls.
    // -------------------------------------------------------------------------
    private val suspiciousPackages = listOf(
        "com.topjohnwu.magisk",
        "io.github.vvb2060.magisk",
        "io.github.vvb2060.magisk.lite",
        "de.robv.android.xposed.installer",
        "org.meowcat.edxposed.manager",
        "org.lsposed.manager",
        "com.tsng.hidemyapplist",
        "cn.geektang.privacyspace",
        "io.github.lsposed.manager",
        "com.lsposed.manager",
        "moe.shizuku.privileged.api",       // Shizuku
        "com.sukisu.ultra",                 // SukiSU Ultra (KernelSU fork)
        "io.github.qauxv",                  // QAuxiliary (Xposed module)
        "com.sevtinge.hyperceiler",         // HyperCeiler (LSPosed module)
        "top.hookvip.pro",                  // HookVIP Pro
        "bin.mt.plus",                      // MT Manager
        "com.byyoung.setting",              // Suspicious settings module
        "org.telegram.messenger",           // Telegram
        "com.discord"                       // Discord
    )

    private fun getPackagesViaShell(): Set<String>? {
        return try {
            val process = Runtime.getRuntime().exec("pm list packages")
            val list = mutableSetOf<String>()
            BufferedReader(InputStreamReader(process.inputStream, StandardCharsets.UTF_8)).use { br ->
                var line = br.readLine()
                while (line != null) {
                    line = line.trim()
                    if (line.length > 8 && line.substring(0, 8).equals("package:", ignoreCase = true)) {
                        val pkg = line.substring(8).trim()
                        if (pkg.isNotEmpty()) list.add(pkg)
                    }
                    line = br.readLine()
                }
            }
            process.destroy()
            if (list.isEmpty()) null else list
        } catch (e: Exception) {
            null
        }
    }

    @SuppressLint("QueryPermissionsNeeded")
    private fun checkPmCommandVsApi(): DetectionResult {
        val shellPackages = getPackagesViaShell()
        if (shellPackages == null) {
            return DetectionResult(
                id = "ruru_pm_cross_method",
                name = context.getString(R.string.chk_ruru_pm_cross_name_error),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_pm_cross_desc_error),
                detailedReason = context.getString(R.string.chk_ruru_pm_cross_reason_error),
                solution = context.getString(R.string.chk_ruru_pm_cross_solution_error),
                technicalDetail = "pm list packages returned null or empty"
            )
        }

        val apiPackages = mutableSetOf<String>()
        try {
            context.packageManager.getInstalledPackages(0).forEach { apiPackages.add(it.packageName) }
            context.packageManager.getInstalledApplications(0).forEach { apiPackages.add(it.packageName) }
        } catch (_: Exception) {}

        // Find packages visible to shell but NOT to the API — these are being hidden
        val hiddenFromApi = suspiciousPackages.filter { pkg ->
            shellPackages.contains(pkg) && !apiPackages.contains(pkg)
        }

        // Also flag suspicious packages visible via API
        val foundViaApi = suspiciousPackages.filter { apiPackages.contains(it) }

        val discrepancies = hiddenFromApi
        return if (discrepancies.isNotEmpty()) {
            DetectionResult(
                id = "ruru_pm_cross_method",
                name = context.getString(R.string.chk_ruru_pm_cross_name),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_pm_cross_desc),
                detailedReason = context.getString(R.string.chk_ruru_pm_cross_reason, discrepancies.joinToString(", ")),
                solution = context.getString(R.string.chk_ruru_pm_cross_solution),
                technicalDetail = "Hidden from API: ${discrepancies.joinToString("; ")}; " +
                    "Found via API: ${foundViaApi.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ruru_pm_cross_method",
                name = context.getString(R.string.chk_ruru_pm_cross_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_pm_cross_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_pm_cross_reason_nd),
                solution = context.getString(R.string.no_action_required),
                technicalDetail = "Shell packages checked: ${suspiciousPackages.size}; " +
                    "API packages total: ${apiPackages.size}"
            )
        }
    }

    // -------------------------------------------------------------------------
    // 8. Xposed module metadata scan
    // Ruru: looks for xposedminversion / xposeddescription in app metadata
    // -------------------------------------------------------------------------
    @SuppressLint("QueryPermissionsNeeded")
    private fun checkXposedModuleMetadata(): DetectionResult {
        val xposedMetaKeys = listOf("xposedminversion", "xposeddescription")
        val foundModules = mutableListOf<String>()

        try {
            val pm = context.packageManager
            val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            for (app in apps) {
                val meta = app.metaData ?: continue
                if (xposedMetaKeys.any { meta.containsKey(it) }) {
                    val label = runCatching { pm.getApplicationLabel(app).toString() }
                        .getOrElse { app.packageName }
                    foundModules.add("$label (${app.packageName})")
                }
            }
        } catch (_: Exception) {}

        return if (foundModules.isNotEmpty()) {
            DetectionResult(
                id = "ruru_xposed_module_metadata",
                name = context.getString(R.string.chk_ruru_xposed_meta_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_xposed_meta_desc),
                detailedReason = context.getString(R.string.chk_ruru_xposed_meta_reason, foundModules.joinToString(", ")),
                solution = context.getString(R.string.chk_ruru_xposed_meta_solution),
                technicalDetail = "Modules: ${foundModules.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ruru_xposed_module_metadata",
                name = context.getString(R.string.chk_ruru_xposed_meta_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_xposed_meta_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_xposed_meta_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 9. LSPatch via appComponentFactory (API 28+)
    // Ruru: checks appComponentFactory attribute for "lsposed" string
    // -------------------------------------------------------------------------
    @SuppressLint("QueryPermissionsNeeded")
    private fun checkLSPatchAppComponentFactory(): DetectionResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return DetectionResult(
                id = "ruru_lspatch_component_factory",
                name = context.getString(R.string.chk_ruru_lspatch_name_skip),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_lspatch_desc_skip),
                detailedReason = context.getString(R.string.chk_ruru_lspatch_reason_skip),
                solution = context.getString(R.string.no_action_required)
            )
        }

        val foundApps = mutableListOf<String>()
        try {
            val pm = context.packageManager
            val intent = android.content.Intent(android.content.Intent.ACTION_MAIN)
            val activities = pm.queryIntentActivities(intent, PackageManager.GET_META_DATA)
            for (resolveInfo in activities) {
                val appInfo = resolveInfo.activityInfo.applicationInfo
                val factory = appInfo.appComponentFactory ?: continue
                if (factory.contains("lsposed", ignoreCase = true) ||
                    factory.contains("lspatch", ignoreCase = true)
                ) {
                    val label = runCatching { pm.getApplicationLabel(appInfo).toString() }
                        .getOrElse { appInfo.packageName }
                    foundApps.add("$label (factory=$factory)")
                }
            }
        } catch (_: Exception) {}

        return if (foundApps.isNotEmpty()) {
            DetectionResult(
                id = "ruru_lspatch_component_factory",
                name = context.getString(R.string.chk_ruru_lspatch_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_lspatch_desc),
                detailedReason = context.getString(R.string.chk_ruru_lspatch_reason, foundApps.joinToString(", ")),
                solution = context.getString(R.string.chk_ruru_lspatch_solution),
                technicalDetail = "LSPatch apps: ${foundApps.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ruru_lspatch_component_factory",
                name = context.getString(R.string.chk_ruru_lspatch_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_lspatch_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_lspatch_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 10. Account list anomaly
    // Ruru: checks AccountManager for any accounts (suspicious presence)
    // -------------------------------------------------------------------------
    private fun checkAccountListAnomaly(): DetectionResult {
        val accountList = mutableListOf<String>()
        try {
            val accounts = AccountManager.get(context).accounts
            for (account in accounts) {
                accountList.add("${account.type}: ${account.name}")
            }
        } catch (_: Exception) {}

        return if (accountList.isNotEmpty()) {
            DetectionResult(
                id = "ruru_account_list",
                name = context.getString(R.string.chk_ruru_account_name),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.INFO,
                description = context.getString(R.string.chk_ruru_account_desc),
                detailedReason = context.getString(R.string.chk_ruru_account_reason, accountList.size, accountList.joinToString(", ")),
                solution = context.getString(R.string.chk_ruru_account_solution),
                technicalDetail = "Accounts: ${accountList.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ruru_account_list",
                name = context.getString(R.string.chk_ruru_account_name),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.INFO,
                description = context.getString(R.string.chk_ruru_account_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_account_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 11. VPN connection detection
    // Ruru: checks tun0/ppp0 network interface or http.proxyHost property
    // -------------------------------------------------------------------------
    private fun checkVpnConnection(): DetectionResult {
        var vpnActive = false
        val indicators = mutableListOf<String>()

        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            for (iface in interfaces) {
                if (iface.isUp && iface.interfaceAddresses.isNotEmpty() &&
                    (iface.name == "tun0" || iface.name == "ppp0")
                ) {
                    vpnActive = true
                    indicators.add("Network interface: ${iface.name}")
                }
            }
        } catch (_: Exception) {}

        try {
            @Suppress("DEPRECATION")
            val connMgr = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            @Suppress("DEPRECATION")
            val vpnInfo = connMgr?.getNetworkInfo(17) // TYPE_VPN = 17
            if (vpnInfo?.isConnectedOrConnecting == true) {
                vpnActive = true
                indicators.add("ConnectivityManager TYPE_VPN connected")
            }
        } catch (_: Exception) {}

        try {
            val proxyHost = System.getProperty("http.proxyHost")
            val proxyPort = System.getProperty("http.proxyPort")?.toIntOrNull() ?: -1
            if (!proxyHost.isNullOrEmpty() && proxyPort != -1) {
                vpnActive = true
                indicators.add("http.proxyHost=$proxyHost:$proxyPort")
            }
        } catch (_: Exception) {}

        return if (vpnActive) {
            DetectionResult(
                id = "ruru_vpn_connection",
                name = context.getString(R.string.chk_ruru_vpn_name),
                category = DetectionCategory.NETWORK,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ruru_vpn_desc),
                detailedReason = context.getString(R.string.chk_ruru_vpn_reason, indicators.joinToString(", ")),
                solution = context.getString(R.string.chk_ruru_vpn_solution),
                technicalDetail = "VPN indicators: ${indicators.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ruru_vpn_connection",
                name = context.getString(R.string.chk_ruru_vpn_name_nd),
                category = DetectionCategory.NETWORK,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ruru_vpn_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_vpn_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 12. Accessibility services scan
    // Ruru: collects enabled accessibility service names + checks isEnabled
    // -------------------------------------------------------------------------
    private fun checkAccessibilityServices(): DetectionResult {
        val serviceNames = mutableListOf<String>()
        var accessibilityEnabled = false

        try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            if (am != null) {
                accessibilityEnabled = am.isEnabled
                val services = am.getEnabledAccessibilityServiceList(
                    android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK
                ) ?: emptyList()
                for (svc in services) {
                    val label = runCatching {
                        context.packageManager.getApplicationLabel(
                            svc.resolveInfo.serviceInfo.applicationInfo
                        ).toString()
                    }.getOrElse { svc.resolveInfo.serviceInfo.packageName }
                    serviceNames.add(label)
                }
            }
        } catch (_: Exception) {}

        // Also query Settings.Secure for completeness
        try {
            val settingValue = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            )
            if (!settingValue.isNullOrEmpty()) {
                val fromSettings = settingValue.split(':')
                    .filter { it.isNotEmpty() && !serviceNames.contains(it) }
                serviceNames.addAll(fromSettings)
            }
            val enabledFlag = Settings.Secure.getInt(
                context.contentResolver,
                Settings.Secure.ACCESSIBILITY_ENABLED, 0
            )
            if (enabledFlag != 0) accessibilityEnabled = true
        } catch (_: Exception) {}

        return if (accessibilityEnabled || serviceNames.isNotEmpty()) {
            DetectionResult(
                id = "ruru_accessibility_services",
                name = context.getString(R.string.chk_ruru_a11y_name),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ruru_a11y_desc),
                detailedReason = context.getString(R.string.chk_ruru_a11y_reason, accessibilityEnabled.toString(), if (serviceNames.isEmpty()) "(none listed)" else serviceNames.joinToString(", ")),
                solution = context.getString(R.string.chk_ruru_a11y_solution),
                technicalDetail = "isEnabled=$accessibilityEnabled; services=${serviceNames.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ruru_accessibility_services",
                name = context.getString(R.string.chk_ruru_a11y_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_ruru_a11y_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_a11y_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }

    // -------------------------------------------------------------------------
    // 13. Package-manager API discrepancy
    // Ruru (PMSundryAPIs): tests getPackageUid / getInstallSourceInfo /
    //                       getLaunchIntentForPackage for known packages
    //                       that should NOT be visible to a normal app if HMA
    //                       is filtering correctly — but a discrepancy between
    //                       these APIs reveals inconsistent filtering.
    // -------------------------------------------------------------------------
    private fun getPackageUidSafe(packageName: String): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return try {
                context.packageManager.getPackageUid(packageName, 0)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
        }
        return false
    }

    private fun getInstallSourceInfoSafe(packageName: String): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return try {
                context.packageManager.getInstallSourceInfo(packageName)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
        }
        return false
    }

    private fun getLaunchIntentSafe(packageName: String): Boolean {
        return context.packageManager.getLaunchIntentForPackage(packageName) != null
    }

    private fun checkPmApiDiscrepancy(): DetectionResult {
        // Build a quick baseline: which suspicious packages are visible via getInstalledPackages
        val apiVisible = suspiciousPackages.filter { pkg ->
            try {
                context.packageManager.getApplicationInfo(pkg, 0)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
        }.toSet()

        // Now test sundry APIs for the same packages
        val discrepancies = mutableListOf<String>()
        for (pkg in suspiciousPackages) {
            val viaUid = getPackageUidSafe(pkg)
            val viaInstallSource = getInstallSourceInfoSafe(pkg)
            val viaLaunchIntent = getLaunchIntentSafe(pkg)
            val visibleViaSundry = viaUid || viaInstallSource || viaLaunchIntent
            val visibleViaBaseline = apiVisible.contains(pkg)

            if (visibleViaSundry != visibleViaBaseline) {
                discrepancies.add(
                    "$pkg (baseline=$visibleViaBaseline uid=$viaUid installSrc=$viaInstallSource launch=$viaLaunchIntent)"
                )
            }
        }

        return if (discrepancies.isNotEmpty()) {
            DetectionResult(
                id = "ruru_pm_api_discrepancy",
                name = context.getString(R.string.chk_ruru_pm_api_name),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_pm_api_desc),
                detailedReason = context.getString(R.string.chk_ruru_pm_api_reason, discrepancies.joinToString(", ")),
                solution = context.getString(R.string.chk_ruru_pm_api_solution),
                technicalDetail = "Discrepancies: ${discrepancies.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "ruru_pm_api_discrepancy",
                name = context.getString(R.string.chk_ruru_pm_api_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_ruru_pm_api_desc_nd),
                detailedReason = context.getString(R.string.chk_ruru_pm_api_reason_nd),
                solution = context.getString(R.string.no_action_required)
            )
        }
    }
}
