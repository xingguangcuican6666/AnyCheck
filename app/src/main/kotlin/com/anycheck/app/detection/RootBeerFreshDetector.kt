package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.anycheck.app.R
import java.io.File
import java.io.InputStream
import java.util.NoSuchElementException
import java.util.Scanner

/**
 * Detection techniques inspired by https://github.com/KimChangYoun/rootbeerFresh.
 *
 * Adds four checks that are not already covered by other AnyCheck detectors:
 *  1. Extended potentially-dangerous apps (black markets, billing hacks, game cheats)
 *  2. Extended root-cloaking apps (Cydia Substrate, HideMyRoot ad-free, HideRoot Premium)
 *  3. PATH environment-variable-based su binary detection
 *  4. SDK-version-aware `mount` command RW-paths check
 */
class RootBeerFreshDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkPotentiallyDangerousApps(),
        checkExtendedRootCloakingApps(),
        checkPathBasedSuBinary(),
        checkMountRWPaths()
    )

    // ---------------------------------------------------------------
    // Check 1: Potentially dangerous / piracy / cheat apps
    // ---------------------------------------------------------------
    private fun checkPotentiallyDangerousApps(): DetectionResult {
        val dangerousApps = mapOf(
            // Lucky Patcher variants
            "com.chelpus.luckypatcher"                          to "Lucky Patcher",
            "com.ramdroid.appquarantinepro"                     to "App Quarantine Pro",
            // Fake in-app billing hijackers
            "com.android.vending.billing.InAppBillingService.COIN" to "InAppBilling COIN hijacker",
            "com.android.vending.billing.InAppBillingService.LUCK" to "InAppBilling LUCK hijacker",
            // Black-market app stores
            "com.blackmartalpha"                                to "BlackMart Alpha",
            "org.blackmart.market"                              to "BlackMart",
            "com.allinone.free"                                 to "AllInOne (black market)",
            "com.repodroid.app"                                 to "RepoDroid",
            "org.creeplays.hack"                                to "CreeHack",
            "com.baseappfull.fwd"                               to "Freedom (in-app bypass)",
            "com.zmapp"                                         to "ZMarket",
            "com.dv.marketmod.installer"                        to "Market Mod Installer",
            "org.mobilism.android"                              to "Mobilism Market",
            // Suspicious/spyware-like packages
            "com.android.wp.net.log"                            to "WP Net Log",
            "com.android.camera.update"                         to "Fake Camera Update",
            // Cheat / game-hack tools
            "cc.madkite.freedom"                                to "Freedom (game IAP bypass)",
            "com.xmodgame"                                      to "XMod Game",
            "com.cih.game_cih"                                  to "Game CIH",
            "com.charles.lpoqasert"                             to "Lpoqasert",
            "catch_.me_.if_.you_.can_"                          to "Catch Me If You Can"
        )
        val found = dangerousApps.filter { packageExists(it.key) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "rootbeerfresh_dangerous_apps",
                name = context.getString(R.string.chk_rootbeerfresh_dangerous_apps_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rootbeerfresh_dangerous_apps_desc),
                detailedReason = context.getString(R.string.chk_rootbeerfresh_dangerous_apps_reason, found.size, found.values.joinToString(", ")),
                solution = context.getString(R.string.chk_rootbeerfresh_dangerous_apps_solution),
                technicalDetail = "Packages: ${found.keys.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "rootbeerfresh_dangerous_apps",
                name = context.getString(R.string.chk_rootbeerfresh_dangerous_apps_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rootbeerfresh_dangerous_apps_desc_nd),
                detailedReason = context.getString(R.string.chk_rootbeerfresh_dangerous_apps_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ---------------------------------------------------------------
    // Check 2: Extended root-cloaking apps (missing from existing check)
    // ---------------------------------------------------------------
    private fun checkExtendedRootCloakingApps(): DetectionResult {
        val cloakingApps = mapOf(
            "com.saurik.substrate"             to "Cydia Substrate (code injection framework)",
            "com.amphoras.hidemyrootadfree"    to "HideMyRoot Ad-Free",
            "com.formyhm.hiderootPremium"      to "HideRoot Premium"
        )
        val found = cloakingApps.filter { packageExists(it.key) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "rootbeerfresh_root_cloaking",
                name = context.getString(R.string.chk_rootbeerfresh_root_cloaking_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rootbeerfresh_root_cloaking_desc),
                detailedReason = context.getString(R.string.chk_rootbeerfresh_root_cloaking_reason, found.values.joinToString(", ")),
                solution = context.getString(R.string.chk_rootbeerfresh_root_cloaking_solution),
                technicalDetail = "Packages: ${found.keys.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "rootbeerfresh_root_cloaking",
                name = context.getString(R.string.chk_rootbeerfresh_root_cloaking_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rootbeerfresh_root_cloaking_desc_nd),
                detailedReason = context.getString(R.string.chk_rootbeerfresh_root_cloaking_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ---------------------------------------------------------------
    // Check 3: PATH environment-variable based su binary detection
    // ---------------------------------------------------------------
    private fun checkPathBasedSuBinary(): DetectionResult {
        val staticPaths = listOf(
            "/data/local/",
            "/data/local/bin/",
            "/data/local/xbin/",
            "/sbin/",
            "/su/bin/",
            "/system/bin/",
            "/system/bin/.ext/",
            "/system/bin/failsafe/",
            "/system/sd/xbin/",
            "/system/usr/we-need-root/",
            "/system/xbin/",
            "/cache/",
            "/data/",
            "/dev/"
        )

        // Dynamically add paths from the PATH environment variable (rootbeerFresh approach)
        val allPaths = staticPaths.toMutableList()
        val envPath = System.getenv("PATH")
        if (!envPath.isNullOrEmpty()) {
            for (p in envPath.split(":")) {
                val normalized = if (p.endsWith("/")) p else "$p/"
                if (!allPaths.contains(normalized)) allPaths.add(normalized)
            }
        }

        val found = allPaths.filter { dir ->
            File(dir, "su").exists()
        }.map { "${it}su" }

        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "rootbeerfresh_path_su",
                name = context.getString(R.string.chk_rootbeerfresh_path_su_name),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_rootbeerfresh_path_su_desc),
                detailedReason = context.getString(R.string.chk_rootbeerfresh_path_su_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_rootbeerfresh_path_su_solution),
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "rootbeerfresh_path_su",
                name = context.getString(R.string.chk_rootbeerfresh_path_su_name_nd),
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_rootbeerfresh_path_su_desc_nd),
                detailedReason = context.getString(R.string.chk_rootbeerfresh_path_su_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ---------------------------------------------------------------
    // Check 4: SDK-version-aware mount-command RW paths check
    // ---------------------------------------------------------------
    private fun checkMountRWPaths(): DetectionResult {
        val pathsThatShouldBeReadOnly = listOf(
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/vendor/bin",
            "/sbin",
            "/etc"
        )

        val lines = runMountCommand() ?: return DetectionResult(
            id = "rootbeerfresh_rw_paths",
            name = context.getString(R.string.chk_rootbeerfresh_rw_paths_name_nd),
            category = DetectionCategory.SYSTEM_INTEGRITY,
            status = DetectionStatus.NOT_DETECTED,
            riskLevel = RiskLevel.HIGH,
            description = context.getString(R.string.chk_rootbeerfresh_rw_paths_desc_error),
            detailedReason = context.getString(R.string.chk_rootbeerfresh_rw_paths_reason_error),
            solution = context.getString(R.string.chk_rootbeerfresh_rw_paths_solution_error)
        )

        val sdkVersion = Build.VERSION.SDK_INT
        val rwPaths = mutableListOf<String>()

        for (line in lines) {
            val args = line.split(" ")
            // Android <= Marshmallow: "<fs_spec> <mountpoint> <type> <options>"  (≥4 tokens)
            // Android >  Marshmallow: "<fs_spec> on <mountpoint> type <type> (<options>)" (≥6 tokens)
            if (sdkVersion <= Build.VERSION_CODES.M && args.size < 4) continue
            if (sdkVersion > Build.VERSION_CODES.M && args.size < 6) continue

            val mountPoint: String
            var mountOptions: String
            if (sdkVersion > Build.VERSION_CODES.M) {
                mountPoint = args[2]
                mountOptions = args[5].removePrefix("(").removeSuffix(")")
            } else {
                mountPoint = args[1]
                mountOptions = args[3]
            }

            if (pathsThatShouldBeReadOnly.any { it.equals(mountPoint, ignoreCase = true) }) {
                if (mountOptions.split(",").any { it.equals("rw", ignoreCase = true) }) {
                    rwPaths.add(mountPoint)
                }
            }
        }

        return if (rwPaths.isNotEmpty()) {
            DetectionResult(
                id = "rootbeerfresh_rw_paths",
                name = context.getString(R.string.chk_rootbeerfresh_rw_paths_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rootbeerfresh_rw_paths_desc, rwPaths.joinToString(", ")),
                detailedReason = context.getString(R.string.chk_rootbeerfresh_rw_paths_reason, rwPaths.joinToString(", ")),
                solution = context.getString(R.string.chk_rootbeerfresh_rw_paths_solution),
                technicalDetail = "RW mounts: ${rwPaths.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "rootbeerfresh_rw_paths",
                name = context.getString(R.string.chk_rootbeerfresh_rw_paths_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rootbeerfresh_rw_paths_desc_nd),
                detailedReason = context.getString(R.string.chk_rootbeerfresh_rw_paths_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun packageExists(packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    private fun runMountCommand(): List<String>? {
        return try {
            val inputStream: InputStream = Runtime.getRuntime().exec("mount").inputStream
                ?: return null
            val text = Scanner(inputStream).useDelimiter("\\A").next()
            text.split("\n")
        } catch (e: Exception) {
            null
        } catch (e: NoSuchElementException) {
            null
        }
    }
}
