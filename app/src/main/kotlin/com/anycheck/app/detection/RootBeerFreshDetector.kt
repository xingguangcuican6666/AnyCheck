package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
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
                name = "Dangerous / Piracy Apps Detected",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Potentially dangerous, piracy, or game-cheat apps found.",
                detailedReason = "Found ${found.size} app(s): ${found.values.joinToString(", ")}. " +
                    "These packages include black-market stores, in-app purchase bypass tools, " +
                    "game cheats, and spyware-like apps. Their presence indicates system compromise " +
                    "or intentional security policy violations.",
                solution = "Uninstall these apps immediately via Settings → Apps or adb uninstall.",
                technicalDetail = "Packages: ${found.keys.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "rootbeerfresh_dangerous_apps",
                name = "Dangerous / Piracy Apps",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No dangerous or piracy apps detected.",
                detailedReason = "None of the known dangerous/piracy/cheat packages were found.",
                solution = "No action required."
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
                name = "Extended Root-Cloaking Apps Detected",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Additional root-hiding or code-injection framework apps detected.",
                detailedReason = "Found: ${found.values.joinToString(", ")}. " +
                    "Cydia Substrate is a runtime code injection framework frequently used to " +
                    "hide root. HideMyRoot and HideRoot variants conceal root indicators from apps.",
                solution = "Uninstall root-cloaking apps via Settings → Apps.",
                technicalDetail = "Packages: ${found.keys.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "rootbeerfresh_root_cloaking",
                name = "Extended Root-Cloaking Apps",
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No additional root-cloaking apps detected.",
                detailedReason = "Cydia Substrate and HideMyRoot/HideRoot variants were not found.",
                solution = "No action required."
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
                name = "SU Binary via PATH Enumeration Detected",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "su binary found via dynamic PATH enumeration.",
                detailedReason = "su binary found at: ${found.joinToString(", ")}. " +
                    "This check dynamically reads the PATH environment variable (like rootbeerFresh) " +
                    "in addition to well-known static paths, catching su binaries placed in " +
                    "non-standard directories that are still on the executable search path.",
                solution = "Remove the su binary and restore a stock system image.",
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "rootbeerfresh_path_su",
                name = "SU Binary via PATH Enumeration",
                category = DetectionCategory.SU_BINARY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No su binary found via PATH enumeration.",
                detailedReason = "su was not found in any static or PATH-derived directory.",
                solution = "No action required."
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
            name = "RW System Paths (mount command)",
            category = DetectionCategory.SYSTEM_INTEGRITY,
            status = DetectionStatus.ERROR,
            riskLevel = RiskLevel.HIGH,
            description = "Could not run mount command.",
            detailedReason = "The mount command returned no output.",
            solution = "Ensure /proc is accessible."
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
                name = "System Paths Mounted Read-Write",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Critical system paths mounted rw: ${rwPaths.joinToString(", ")}.",
                detailedReason = "The following paths that should be read-only are mounted " +
                    "read-write: ${rwPaths.joinToString(", ")}. " +
                    "This is detected by parsing the `mount` command output with " +
                    "SDK-version-aware field offsets (rootbeerFresh technique). " +
                    "A rw-mounted /system indicates the system partition has been modified.",
                solution = "Remount system partition as read-only: `adb shell mount -o remount,ro /system`.",
                technicalDetail = "RW mounts: ${rwPaths.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "rootbeerfresh_rw_paths",
                name = "System Paths Mount Check",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No critical system paths mounted read-write.",
                detailedReason = "mount command output shows all sensitive paths are read-only.",
                solution = "No action required."
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
