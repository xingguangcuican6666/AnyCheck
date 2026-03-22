package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.anycheck.app.R
import java.io.File

/**
 * Detection checks using the RikkaX DeviceCompatibility library approach
 * (https://github.com/RikkaApps/RikkaX/tree/master/compatibility).
 *
 * RikkaX uses `android.os.SystemProperties` and `Build.*` fields to identify OEM
 * ROM flavours.  We extend the same idea — reading system properties via `getprop`
 * — to detect OEM-specific root-access settings, custom ROMs, and manufacturer
 * security indicators that are not covered by the other detector modules.
 *
 * Checks (10 total):
 *  1. MIUI root-access setting  (persist.sys.root_access)
 *  2. LineageOS / CyanogenMod ROM  (ro.lineage.version / ro.cm.version)
 *  3. OEM bootloader unlock flag  (sys.oem_unlock_allowed)
 *  4. Samsung Knox warranty bit  (ro.boot.warranty_bit)
 *  5. Huawei EMUI / HarmonyOS props  (ro.build.version.emui / ro.build.version.hmos)
 *  6. Flyme / Meizu OS  (Build.FINGERPRINT / Build.DISPLAY)
 *  7. ColorOS / OxygenOS / OnePlus ROM  (ro.build.version.opporom / ro.oxygen.version)
 *  8. MIUI HyperOS / MIUI EU props  (ro.miui.ui.version.name + ro.miui.region)
 *  9. Seccomp status  (/proc/self/status → Seccomp: field)
 * 10. Core crack / Lucky Patcher PM integrity check
 */
class RikkaXInspiredDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkMiuiRootAccess(),
        checkLineageOsRom(),
        checkOemUnlockAllowed(),
        checkSamsungKnoxWarranty(),
        checkHuaweiEmuiProps(),
        checkFlymeDevice(),
        checkColorOsOnePlusRom(),
        checkMiuiHyperOsRegion(),
        checkSeccompStatus(),
        checkCoreCrack()
    )

    // ----------------------------------------------------------------
    // Check 1: MIUI root-access property
    // MIUI stores the root grant mode in persist.sys.root_access:
    //   0 = disabled, 1 = ADB only, 2 = Apps only, 3 = ADB + Apps
    // ----------------------------------------------------------------
    private fun checkMiuiRootAccess(): DetectionResult {
        val miuiVersion = getSystemProperty("ro.miui.ui.version.name")
        val rootAccess  = getSystemProperty("persist.sys.root_access")

        if (miuiVersion.isEmpty()) {
            // Not a MIUI device – report as informational
            return DetectionResult(
                id = "rikkax_miui_root_access",
                name = context.getString(R.string.chk_rikkax_miui_root_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_rikkax_miui_root_desc_nd),
                detailedReason = context.getString(R.string.chk_rikkax_miui_root_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "ro.miui.ui.version.name is empty (not MIUI)"
            )
        }

        return when (rootAccess) {
            "3" -> DetectionResult(
                id = "rikkax_miui_root_access",
                name = context.getString(R.string.chk_rikkax_miui_root_name_full),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rikkax_miui_root_desc_full),
                detailedReason = context.getString(R.string.chk_rikkax_miui_root_reason_full, miuiVersion),
                solution = context.getString(R.string.chk_rikkax_miui_root_solution),
                technicalDetail = "persist.sys.root_access=$rootAccess ro.miui.ui.version.name=$miuiVersion"
            )
            "2" -> DetectionResult(
                id = "rikkax_miui_root_access",
                name = context.getString(R.string.chk_rikkax_miui_root_name_apps),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rikkax_miui_root_desc_apps),
                detailedReason = context.getString(R.string.chk_rikkax_miui_root_reason_apps, miuiVersion),
                solution = context.getString(R.string.chk_rikkax_miui_root_solution),
                technicalDetail = "persist.sys.root_access=$rootAccess ro.miui.ui.version.name=$miuiVersion"
            )
            "1" -> DetectionResult(
                id = "rikkax_miui_root_access",
                name = context.getString(R.string.chk_rikkax_miui_root_name_adb),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_rikkax_miui_root_desc_adb),
                detailedReason = context.getString(R.string.chk_rikkax_miui_root_reason_adb, miuiVersion),
                solution = context.getString(R.string.chk_rikkax_miui_root_solution),
                technicalDetail = "persist.sys.root_access=$rootAccess ro.miui.ui.version.name=$miuiVersion"
            )
            else -> DetectionResult(
                id = "rikkax_miui_root_access",
                name = context.getString(R.string.chk_rikkax_miui_root_name_miui_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_rikkax_miui_root_desc_miui_nd),
                detailedReason = context.getString(R.string.chk_rikkax_miui_root_reason_miui_nd, miuiVersion, rootAccess.ifEmpty { "0" }),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "persist.sys.root_access=${rootAccess.ifEmpty { "0" }} ro.miui.ui.version.name=$miuiVersion"
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 2: LineageOS / CyanogenMod ROM
    // ro.lineage.version (LineageOS) or ro.cm.version (CyanogenMod)
    // The presence of a custom AOSP ROM is a moderate security signal.
    // ----------------------------------------------------------------
    private fun checkLineageOsRom(): DetectionResult {
        val lineageVersion = getSystemProperty("ro.lineage.version")
        val cmVersion      = getSystemProperty("ro.cm.version")
        val lineageDevice  = getSystemProperty("ro.lineage.device")

        val version = lineageVersion.ifEmpty { cmVersion }
        val romName = when {
            lineageVersion.isNotEmpty() -> "LineageOS"
            cmVersion.isNotEmpty()      -> "CyanogenMod"
            else                        -> ""
        }

        return if (version.isNotEmpty()) {
            DetectionResult(
                id = "rikkax_lineage_rom",
                name = context.getString(R.string.chk_rikkax_lineage_name, romName),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_rikkax_lineage_desc, romName),
                detailedReason = context.getString(R.string.chk_rikkax_lineage_reason, romName, version, lineageDevice),
                solution = context.getString(R.string.chk_rikkax_lineage_solution),
                technicalDetail = "ro.lineage.version=$lineageVersion ro.cm.version=$cmVersion ro.lineage.device=$lineageDevice"
            )
        } else {
            DetectionResult(
                id = "rikkax_lineage_rom",
                name = context.getString(R.string.chk_rikkax_lineage_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_rikkax_lineage_desc_nd),
                detailedReason = context.getString(R.string.chk_rikkax_lineage_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "ro.lineage.version is empty; ro.cm.version is empty"
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 3: OEM bootloader unlock flag
    // sys.oem_unlock_allowed=1 means the OEM unlock option is currently
    // enabled in Developer Options — a prerequisite for bootloader unlock.
    // ----------------------------------------------------------------
    private fun checkOemUnlockAllowed(): DetectionResult {
        val oemUnlockAllowed  = getSystemProperty("sys.oem_unlock_allowed")
        val oemUnlockSupport  = getSystemProperty("ro.oem_unlock_supported")

        return if (oemUnlockAllowed == "1") {
            DetectionResult(
                id = "rikkax_oem_unlock",
                name = context.getString(R.string.chk_rikkax_oem_unlock_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rikkax_oem_unlock_desc),
                detailedReason = context.getString(R.string.chk_rikkax_oem_unlock_reason),
                solution = context.getString(R.string.chk_rikkax_oem_unlock_solution),
                technicalDetail = "sys.oem_unlock_allowed=$oemUnlockAllowed ro.oem_unlock_supported=$oemUnlockSupport"
            )
        } else {
            DetectionResult(
                id = "rikkax_oem_unlock",
                name = context.getString(R.string.chk_rikkax_oem_unlock_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rikkax_oem_unlock_desc_nd),
                detailedReason = context.getString(R.string.chk_rikkax_oem_unlock_reason_nd, oemUnlockAllowed.ifEmpty { "0" }),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "sys.oem_unlock_allowed=${oemUnlockAllowed.ifEmpty { "0" }}"
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 4: Samsung Knox warranty bit
    // ro.boot.warranty_bit=1 means root/unofficial firmware has been
    // flashed at least once, permanently tripping the Knox counter.
    // ----------------------------------------------------------------
    private fun checkSamsungKnoxWarranty(): DetectionResult {
        val isSamsung    = Build.MANUFACTURER.equals("samsung", ignoreCase = true)
        val warrantyBit  = getSystemProperty("ro.boot.warranty_bit")
        val knoxCounter  = getSystemProperty("ro.boot.knox_active")

        if (!isSamsung) {
            return DetectionResult(
                id = "rikkax_samsung_knox",
                name = context.getString(R.string.chk_rikkax_knox_name_na),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rikkax_knox_desc_na),
                detailedReason = context.getString(R.string.chk_rikkax_knox_reason_na, Build.MANUFACTURER),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "Build.MANUFACTURER=${Build.MANUFACTURER} (not Samsung)"
            )
        }

        return if (warrantyBit == "1") {
            DetectionResult(
                id = "rikkax_samsung_knox",
                name = context.getString(R.string.chk_rikkax_knox_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rikkax_knox_desc),
                detailedReason = context.getString(R.string.chk_rikkax_knox_reason),
                solution = context.getString(R.string.chk_rikkax_knox_solution),
                technicalDetail = "ro.boot.warranty_bit=$warrantyBit ro.boot.knox_active=$knoxCounter"
            )
        } else {
            DetectionResult(
                id = "rikkax_samsung_knox",
                name = context.getString(R.string.chk_rikkax_knox_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rikkax_knox_desc_nd),
                detailedReason = context.getString(R.string.chk_rikkax_knox_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "ro.boot.warranty_bit=${warrantyBit.ifEmpty { "0" }}"
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 5: Huawei EMUI / HarmonyOS device detection
    // Inspired by RikkaX DeviceCompatibility.isEmui() which reads
    // ro.build.version.emui.  We also check HarmonyOS (ro.build.version.hmos)
    // and surface any Huawei-specific root-access properties.
    // ----------------------------------------------------------------
    private fun checkHuaweiEmuiProps(): DetectionResult {
        val emuiVersion = getSystemProperty("ro.build.version.emui")
        val hmosVersion = getSystemProperty("ro.build.version.hmos")
        val isHuawei    = Build.MANUFACTURER.equals("huawei", ignoreCase = true) ||
                          Build.BRAND.equals("honor", ignoreCase = true)

        val detectedVersion = emuiVersion.ifEmpty { hmosVersion }
        val romLabel = when {
            hmosVersion.isNotEmpty() -> "HarmonyOS $hmosVersion"
            emuiVersion.isNotEmpty() -> "EMUI $emuiVersion"
            else                     -> ""
        }

        // Huawei engineering / developer mode root indicator
        val devRootProp = getSystemProperty("ro.product.build.type")
        val isEngBuild  = devRootProp.equals("eng", ignoreCase = true) ||
                          devRootProp.equals("userdebug", ignoreCase = true)

        return if (detectedVersion.isNotEmpty() || isHuawei) {
            if (isEngBuild) {
                DetectionResult(
                    id = "rikkax_emui_props",
                    name = context.getString(R.string.chk_rikkax_emui_name_eng),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_rikkax_emui_desc_eng),
                    detailedReason = context.getString(R.string.chk_rikkax_emui_reason_eng, romLabel, devRootProp),
                    solution = context.getString(R.string.chk_rikkax_emui_solution),
                    technicalDetail = "ro.build.version.emui=$emuiVersion ro.build.version.hmos=$hmosVersion ro.product.build.type=$devRootProp"
                )
            } else {
                DetectionResult(
                    id = "rikkax_emui_props",
                    name = context.getString(R.string.chk_rikkax_emui_name_pass, romLabel.ifEmpty { Build.MANUFACTURER }),
                    category = DetectionCategory.ENVIRONMENT,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.LOW,
                    description = context.getString(R.string.chk_rikkax_emui_desc_pass),
                    detailedReason = context.getString(R.string.chk_rikkax_emui_reason_pass, romLabel.ifEmpty { Build.MANUFACTURER }),
                    solution = context.getString(R.string.chk_no_action_needed),
                    technicalDetail = "ro.build.version.emui=$emuiVersion ro.build.version.hmos=$hmosVersion"
                )
            }
        } else {
            DetectionResult(
                id = "rikkax_emui_props",
                name = context.getString(R.string.chk_rikkax_emui_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.LOW,
                description = context.getString(R.string.chk_rikkax_emui_desc_nd),
                detailedReason = context.getString(R.string.chk_rikkax_emui_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "ro.build.version.emui is empty; ro.build.version.hmos is empty"
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 6: Flyme / Meizu OS
    // Inspired by RikkaX DeviceCompatibility.isFlyme() which checks
    // Build.FINGERPRINT and Build.DISPLAY for the "Flyme" string.
    // ----------------------------------------------------------------
    private fun checkFlymeDevice(): DetectionResult {
        val fingerprint = Build.FINGERPRINT ?: ""
        val display     = Build.DISPLAY ?: ""
        val manufacturer = Build.MANUFACTURER ?: ""

        val isMeizuByManufacturer = manufacturer.equals("meizu", ignoreCase = true)
        val isFlymeFingerprint    = fingerprint.contains("Flyme", ignoreCase = true)
        val isFlymeDisplay        = display.contains("Flyme", ignoreCase = true)
        val isFlyme = isMeizuByManufacturer || isFlymeFingerprint || isFlymeDisplay

        // Also read the Flyme version property used by some Meizu builds
        val flymeVersion = getSystemProperty("ro.flyme.version").ifEmpty {
            getSystemProperty("ro.build.display.id").let { id ->
                if (id.contains("Flyme", ignoreCase = true)) id else ""
            }
        }

        return if (isFlyme) {
            DetectionResult(
                id = "rikkax_flyme_device",
                name = context.getString(R.string.chk_rikkax_flyme_name_pass),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.LOW,
                description = context.getString(R.string.chk_rikkax_flyme_desc_pass),
                detailedReason = context.getString(R.string.chk_rikkax_flyme_reason_pass, flymeVersion.ifEmpty { display }),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "Build.MANUFACTURER=$manufacturer Build.DISPLAY=$display flymeVersion=$flymeVersion"
            )
        } else {
            DetectionResult(
                id = "rikkax_flyme_device",
                name = context.getString(R.string.chk_rikkax_flyme_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.LOW,
                description = context.getString(R.string.chk_rikkax_flyme_desc_nd),
                detailedReason = context.getString(R.string.chk_rikkax_flyme_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "Build.MANUFACTURER=$manufacturer; no Flyme indicator in fingerprint or display"
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 7: ColorOS / OxygenOS / OnePlus ROM
    // ColorOS (Oppo/Realme): ro.build.version.opporom or ro.build.version.oplusrom
    // OxygenOS (OnePlus):     ro.oxygen.version or ro.build.version.ota
    // ----------------------------------------------------------------
    private fun checkColorOsOnePlusRom(): DetectionResult {
        val colorOsVersion  = getSystemProperty("ro.build.version.opporom").ifEmpty {
            getSystemProperty("ro.build.version.oplusrom")
        }
        val oxygenVersion   = getSystemProperty("ro.oxygen.version")
        val oplusBrand      = getSystemProperty("ro.product.brand").let { b ->
            b.equals("oppo", ignoreCase = true) || b.equals("realme", ignoreCase = true) ||
            b.equals("oneplus", ignoreCase = true)
        }
        val manufacturerMatch = Build.MANUFACTURER.equals("oppo", ignoreCase = true) ||
                                Build.MANUFACTURER.equals("realme", ignoreCase = true) ||
                                Build.MANUFACTURER.equals("oneplus", ignoreCase = true) ||
                                Build.BRAND.equals("oneplus", ignoreCase = true)

        val detectedVersion = colorOsVersion.ifEmpty { oxygenVersion }
        val romLabel = when {
            oxygenVersion.isNotEmpty()  -> "OxygenOS $oxygenVersion"
            colorOsVersion.isNotEmpty() -> "ColorOS $colorOsVersion"
            else                        -> ""
        }

        return if (detectedVersion.isNotEmpty() || manufacturerMatch || oplusBrand) {
            DetectionResult(
                id = "rikkax_color_os",
                name = context.getString(R.string.chk_rikkax_color_os_name_pass, romLabel.ifEmpty { Build.MANUFACTURER }),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.LOW,
                description = context.getString(R.string.chk_rikkax_color_os_desc_pass),
                detailedReason = context.getString(R.string.chk_rikkax_color_os_reason_pass, romLabel.ifEmpty { Build.MANUFACTURER }),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "ro.build.version.opporom=$colorOsVersion ro.oxygen.version=$oxygenVersion Build.MANUFACTURER=${Build.MANUFACTURER}"
            )
        } else {
            DetectionResult(
                id = "rikkax_color_os",
                name = context.getString(R.string.chk_rikkax_color_os_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.LOW,
                description = context.getString(R.string.chk_rikkax_color_os_desc_nd),
                detailedReason = context.getString(R.string.chk_rikkax_color_os_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "ro.build.version.opporom is empty; ro.oxygen.version is empty"
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 8: MIUI HyperOS / MIUI EU region
    // Inspired by RikkaX DeviceCompatibility.isMiui() (reads
    // ro.miui.ui.version.name) and getRegionForMiui() (reads ro.miui.region).
    // MIUI EU is a third-party MIUI port with different security defaults.
    // HyperOS is Xiaomi's successor to MIUI.
    // ----------------------------------------------------------------
    private fun checkMiuiHyperOsRegion(): DetectionResult {
        val miuiVersion  = getSystemProperty("ro.miui.ui.version.name")
        val miuiRegion   = getSystemProperty("ro.miui.region")
        val hyperOsVer   = getSystemProperty("ro.mi.os.version.name")
        val hyperOsCode  = getSystemProperty("ro.mi.os.version.incremental")

        val isHyperOs = hyperOsVer.isNotEmpty() || hyperOsCode.isNotEmpty()
        val isMiui    = miuiVersion.isNotEmpty()

        if (!isMiui && !isHyperOs) {
            return DetectionResult(
                id = "rikkax_miui_region",
                name = context.getString(R.string.chk_rikkax_miui_region_name_nd),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.LOW,
                description = context.getString(R.string.chk_rikkax_miui_region_desc_nd),
                detailedReason = context.getString(R.string.chk_rikkax_miui_region_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "ro.miui.ui.version.name is empty; ro.mi.os.version.name is empty"
            )
        }

        val romLabel = when {
            isHyperOs -> "HyperOS ${hyperOsVer.ifEmpty { hyperOsCode }}"
            else      -> "MIUI $miuiVersion"
        }

        // MIUI EU is a community-maintained MIUI port; official regions are "CN", "GLOBAL", "EEA", "IN", etc.
        val isEuRom = miuiVersion.contains("EU", ignoreCase = true) &&
                      !miuiVersion.contains("EEA", ignoreCase = true) ||
                      miuiRegion.equals("EU", ignoreCase = true)

        return if (isEuRom) {
            DetectionResult(
                id = "rikkax_miui_region",
                name = context.getString(R.string.chk_rikkax_miui_region_name_eu),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_rikkax_miui_region_desc_eu),
                detailedReason = context.getString(R.string.chk_rikkax_miui_region_reason_eu, romLabel, miuiRegion),
                solution = context.getString(R.string.chk_rikkax_miui_region_solution_eu),
                technicalDetail = "ro.miui.ui.version.name=$miuiVersion ro.miui.region=$miuiRegion ro.mi.os.version.name=$hyperOsVer"
            )
        } else {
            DetectionResult(
                id = "rikkax_miui_region",
                name = context.getString(R.string.chk_rikkax_miui_region_name_pass, romLabel),
                category = DetectionCategory.ENVIRONMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.LOW,
                description = context.getString(R.string.chk_rikkax_miui_region_desc_pass),
                detailedReason = context.getString(R.string.chk_rikkax_miui_region_reason_pass, romLabel, miuiRegion.ifEmpty { "CN/GLOBAL" }),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "ro.miui.ui.version.name=$miuiVersion ro.miui.region=$miuiRegion ro.mi.os.version.name=$hyperOsVer"
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 9: Seccomp status
    // /proc/self/status contains a "Seccomp:" line.
    //   0 = disabled (anomalous: kernel does not enforce Seccomp)
    //   1 = strict mode (rare on normal Android processes)
    //   2 = filter mode (normal for Android 5.0+ processes)
    // A value of 0 indicates a kernel that has Seccomp disabled or stripped,
    // which is associated with modified/insecure kernels used by some root
    // solutions to weaken process isolation.
    // ----------------------------------------------------------------
    private fun checkSeccompStatus(): DetectionResult {
        return try {
            val statusText = File("/proc/self/status").readText()
            val seccompLine = statusText.lines().firstOrNull { it.trimStart().startsWith("Seccomp:") }
            val seccompValue = seccompLine?.substringAfter(":")?.trim()?.toIntOrNull()

            when (seccompValue) {
                0 -> DetectionResult(
                    id = "rikkax_seccomp",
                    name = context.getString(R.string.chk_rikkax_seccomp_name_zero),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_rikkax_seccomp_desc_zero),
                    detailedReason = context.getString(R.string.chk_rikkax_seccomp_reason_zero),
                    solution = context.getString(R.string.chk_rikkax_seccomp_solution_zero),
                    technicalDetail = "Seccomp=$seccompValue (from /proc/self/status)"
                )
                null -> DetectionResult(
                    id = "rikkax_seccomp",
                    name = context.getString(R.string.chk_rikkax_seccomp_name_missing),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.ERROR,
                    riskLevel = RiskLevel.MEDIUM,
                    description = context.getString(R.string.chk_rikkax_seccomp_desc_missing),
                    detailedReason = context.getString(R.string.chk_rikkax_seccomp_reason_missing),
                    solution = context.getString(R.string.chk_rikkax_seccomp_solution_missing),
                    technicalDetail = "Seccomp line not found in /proc/self/status"
                )
                else -> DetectionResult(
                    id = "rikkax_seccomp",
                    name = context.getString(R.string.chk_rikkax_seccomp_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_rikkax_seccomp_desc_nd, seccompValue),
                    detailedReason = context.getString(R.string.chk_rikkax_seccomp_reason_nd, seccompValue),
                    solution = context.getString(R.string.chk_no_action_needed),
                    technicalDetail = "Seccomp=$seccompValue (from /proc/self/status)"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "rikkax_seccomp",
                name = context.getString(R.string.chk_rikkax_seccomp_name_error),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.MEDIUM,
                description = context.getString(R.string.chk_rikkax_seccomp_desc_error),
                detailedReason = context.getString(R.string.chk_rikkax_seccomp_reason_error),
                solution = context.getString(R.string.chk_rikkax_seccomp_solution_error),
                technicalDetail = context.getString(R.string.err_detail_error, e.message ?: "unknown")
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 10: Core crack / Lucky Patcher PackageManager integrity
    // "Core crack" (核心破解) patches the Android framework
    // (PackageManagerService) to bypass APK signature verification, allowing
    // apps with mismatched or forged signatures to be installed. Lucky Patcher
    // is the most common tool that enables this.
    //
    // Detection approach:
    //  a) Lucky Patcher billing-bypass packages (injected fake Google billing)
    //  b) System-level Lucky Patcher artifacts (files/dirs patched into /system)
    //  c) Non-system apps holding android.permission.INSTALL_PACKAGES — a
    //     permission that should only be granted to system apps; its presence
    //     on a non-system app is a strong PM tampering indicator
    // ----------------------------------------------------------------
    private fun checkCoreCrack(): DetectionResult {
        // Lucky Patcher billing-intercept / core-crack helper packages
        val coreCrackPkgs = listOf(
            "cc.luckypatcher",
            "com.luckypatcher",
            "cc.meditato.luckypatcher",
            "com.forpda.lp",
            "cc.happylife.luckypatcher"
        )

        // Files that indicate Lucky Patcher has patched the system framework
        val coreCrackFiles = listOf(
            "/system/app/LuckyPatcher",
            "/system/priv-app/LuckyPatcher",
            "/system/app/LuckyPatcher.apk",
            "/system/priv-app/LuckyPatcher.apk",
            "/data/system/lp_install.log",
            "/data/system/lp_backup"
        )

        val foundPkgs  = coreCrackPkgs.filter  { packageExists(it) }
        val foundFiles = coreCrackFiles.filter { File(it).exists() }

        // PM permission anomaly: a non-system app that holds
        // android.permission.INSTALL_PACKAGES is a strong indicator that the
        // PackageManager has been tampered to grant install-bypass permissions.
        val pmAnomalyPkgs = mutableListOf<String>()
        try {
            @Suppress("DEPRECATION")
            context.packageManager
                .getInstalledPackages(PackageManager.GET_PERMISSIONS)
                .forEach { pkg ->
                    val isSystem = (pkg.applicationInfo.flags and
                        android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    if (!isSystem &&
                        pkg.requestedPermissions?.contains(
                            "android.permission.INSTALL_PACKAGES"
                        ) == true
                    ) {
                        pmAnomalyPkgs.add(pkg.packageName)
                    }
                }
        } catch (_: Exception) {}

        val indicators = mutableListOf<String>()
        if (foundPkgs.isNotEmpty())     indicators.add("Packages: ${foundPkgs.joinToString()}")
        if (foundFiles.isNotEmpty())    indicators.add("Files: ${foundFiles.joinToString()}")
        if (pmAnomalyPkgs.isNotEmpty()) indicators.add("PM anomaly (non-system INSTALL_PACKAGES): ${pmAnomalyPkgs.joinToString()}")

        return if (indicators.isNotEmpty()) {
            DetectionResult(
                id = "rikkax_core_crack",
                name = context.getString(R.string.chk_rikkax_core_crack_name),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rikkax_core_crack_desc),
                detailedReason = context.getString(R.string.chk_rikkax_core_crack_reason, indicators.joinToString("; ")),
                solution = context.getString(R.string.chk_rikkax_core_crack_solution),
                technicalDetail = indicators.joinToString("\n")
            )
        } else {
            DetectionResult(
                id = "rikkax_core_crack",
                name = context.getString(R.string.chk_rikkax_core_crack_name_nd),
                category = DetectionCategory.ROOT_MANAGEMENT,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_rikkax_core_crack_desc_nd),
                detailedReason = context.getString(R.string.chk_rikkax_core_crack_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ----------------------------------------------------------------
    // Utility: run `getprop <name>` and return the trimmed value
    // (same approach as SystemIntegrityDetector)
    // ----------------------------------------------------------------
    private fun getSystemProperty(name: String): String = try {
        val process = Runtime.getRuntime().exec(arrayOf("getprop", name))
        val result = process.inputStream.bufferedReader().readLine()?.trim() ?: ""
        process.waitFor()
        result
    } catch (_: Exception) {
        ""
    }

    private fun packageExists(packageName: String): Boolean = try {
        context.packageManager.getPackageInfo(packageName, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }
}
