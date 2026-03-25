package com.anycheck.app.detection

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.anycheck.app.R
import java.io.File
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory

/**
 * Checks that validate the hardware-backed security posture of the device:
 *  1. AVB (Android Verified Boot) -- checks ro.boot.verifiedbootstate
 *  2. TEE -- actually generates a key and inspects KeyInfo to confirm hardware backing
 *     (property-based checks can be spoofed by Magisk)
 *  3. Hardware-backed RSA key attestation -- second-factor confirmation
 *  4. Suspicious root daemon processes -- lspd, magiskd, ksud, zygiskd, riru, etc.
 *  5. System property tampering -- cross-reference fingerprint vs build props, Build.* vs getprop
 *  6. Extended su binary scan -- comprehensive path list + PATH-based discovery
 */
class SystemIntegrityDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkAvbBootState(),
        checkTeeHardwareBacked(),
        checkKeystoreAttestation(),
        checkSuspiciousRootDaemons(),
        checkPropTampering(),
        checkSuExtended(),
        checkSnapdragonSecurityPatch()
    )

    // ----------------------------------------------------------------
    // Check 1: Android Verified Boot (AVB) state
    // ----------------------------------------------------------------
    private fun checkAvbBootState(): DetectionResult {
        return try {
            val verifiedBootState = getSystemProperty("ro.boot.verifiedbootstate")
            val verityMode = getSystemProperty("ro.boot.veritymode")
            val bootState = getSystemProperty("ro.boot.flash.locked")

            when {
                verifiedBootState.equals("green", ignoreCase = true) -> {
                    DetectionResult(
                        id = "avb_boot_state",
                        name = context.getString(R.string.chk_avb_boot_state_name_nd),
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.NOT_DETECTED,
                        riskLevel = RiskLevel.CRITICAL,
                        description = context.getString(R.string.chk_avb_boot_state_desc_green),
                        detailedReason = context.getString(R.string.chk_avb_boot_state_reason_green, verifiedBootState),
                        solution = context.getString(R.string.chk_no_action_needed)
                    )
                }
                verifiedBootState.equals("yellow", ignoreCase = true) -> {
                    DetectionResult(
                        id = "avb_boot_state",
                        name = context.getString(R.string.chk_avb_boot_state_name_yellow),
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.DETECTED,
                        riskLevel = RiskLevel.HIGH,
                        description = context.getString(R.string.chk_avb_boot_state_desc_yellow),
                        detailedReason = context.getString(R.string.chk_avb_boot_state_reason_yellow, verifiedBootState),
                        solution = context.getString(R.string.chk_avb_boot_state_solution_yellow),
                        technicalDetail = "verifiedbootstate=$verifiedBootState veritymode=$verityMode"
                    )
                }
                verifiedBootState.equals("orange", ignoreCase = true) -> {
                    DetectionResult(
                        id = "avb_boot_state",
                        name = context.getString(R.string.chk_avb_boot_state_name_orange),
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.DETECTED,
                        riskLevel = RiskLevel.CRITICAL,
                        description = context.getString(R.string.chk_avb_boot_state_desc_orange),
                        detailedReason = context.getString(R.string.chk_avb_boot_state_reason_orange, verifiedBootState),
                        solution = context.getString(R.string.chk_avb_boot_state_solution_orange),
                        technicalDetail = "verifiedbootstate=$verifiedBootState flash.locked=$bootState"
                    )
                }
                verifiedBootState.equals("red", ignoreCase = true) -> {
                    DetectionResult(
                        id = "avb_boot_state",
                        name = context.getString(R.string.chk_avb_boot_state_name_red),
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.DETECTED,
                        riskLevel = RiskLevel.CRITICAL,
                        description = context.getString(R.string.chk_avb_boot_state_desc_red),
                        detailedReason = context.getString(R.string.chk_avb_boot_state_reason_red, verifiedBootState),
                        solution = context.getString(R.string.chk_avb_boot_state_solution_red),
                        technicalDetail = "verifiedbootstate=$verifiedBootState"
                    )
                }
                verifiedBootState.isNotEmpty() -> {
                    DetectionResult(
                        id = "avb_boot_state",
                        name = context.getString(R.string.chk_avb_boot_state_name_unknown),
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.DETECTED,
                        riskLevel = RiskLevel.HIGH,
                        description = context.getString(R.string.chk_avb_boot_state_desc_unknown, verifiedBootState),
                        detailedReason = context.getString(R.string.chk_avb_boot_state_reason_unknown, verifiedBootState),
                        solution = context.getString(R.string.chk_avb_boot_state_solution_unknown),
                        technicalDetail = "verifiedbootstate=$verifiedBootState"
                    )
                }
                else -> {
                    DetectionResult(
                        id = "avb_boot_state",
                        name = context.getString(R.string.chk_avb_boot_state_name_nd),
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.NOT_DETECTED,
                        riskLevel = RiskLevel.HIGH,
                        description = context.getString(R.string.chk_avb_boot_state_desc_nd),
                        detailedReason = context.getString(R.string.chk_avb_boot_state_reason_nd),
                        solution = context.getString(R.string.chk_no_action_needed),
                        technicalDetail = "verifiedbootstate=(empty) veritymode=$verityMode"
                    )
                }
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "avb_boot_state",
                name = context.getString(R.string.chk_avb_boot_state_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_avb_boot_state_desc_error),
                detailedReason = context.getString(R.string.chk_avb_boot_state_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 2: TEE -- actual AES key generation + KeyInfo hardware verification
    //
    // Property-based checks (ro.hardware.keystore, ro.tee.type, etc.) can be
    // trivially spoofed by Magisk resetprop. Instead, we generate a real AES key
    // via AndroidKeyStore and inspect whether TEE backed its creation.
    // This exercises the actual Keymaster/KeyMint HAL via Binder, which Magisk
    // cannot intercept without a kernel module.
    // ----------------------------------------------------------------
    private fun checkTeeHardwareBacked(): DetectionResult {
        return try {
            val keyAlias = "anycheck_tee_probe_${System.currentTimeMillis()}"
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
            )
            val spec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false)
                .build()
            keyGenerator.init(spec)
            keyGenerator.generateKey()

            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val secretKey = keyStore.getKey(keyAlias, null) as javax.crypto.SecretKey

            val securityLevelStr: String
            val isHardwareBacked: Boolean

            val factory = SecretKeyFactory.getInstance(secretKey.algorithm, "AndroidKeyStore")
            val info = factory.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                isHardwareBacked = info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                    info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
                securityLevelStr = when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox HSM"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                    else -> "Software"
                }
            } else {
                @Suppress("DEPRECATION")
                isHardwareBacked = info.isInsideSecureHardware
                securityLevelStr = if (isHardwareBacked) "TEE" else "Software"
            }

            runCatching { keyStore.deleteEntry(keyAlias) }

            if (isHardwareBacked) {
                DetectionResult(
                    id = "tee_hardware_backed",
                    name = context.getString(R.string.chk_tee_hardware_backed_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_tee_hardware_backed_desc_nd, securityLevelStr),
                    detailedReason = context.getString(R.string.chk_tee_hardware_backed_reason_nd, securityLevelStr),
                    solution = context.getString(R.string.chk_no_action_needed),
                    technicalDetail = "security_level=$securityLevelStr sdk=${Build.VERSION.SDK_INT}"
                )
            } else {
                DetectionResult(
                    id = "tee_hardware_backed",
                    name = context.getString(R.string.chk_tee_hardware_backed_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_tee_hardware_backed_desc),
                    detailedReason = context.getString(R.string.chk_tee_hardware_backed_reason),
                    solution = context.getString(R.string.chk_tee_hardware_backed_solution),
                    technicalDetail = "security_level=software sdk=${Build.VERSION.SDK_INT}"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "tee_hardware_backed",
                name = context.getString(R.string.chk_tee_hardware_backed_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_tee_hardware_backed_desc_error),
                detailedReason = context.getString(R.string.chk_tee_hardware_backed_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 3: Hardware-backed keystore attestation (RSA second factor)
    // ----------------------------------------------------------------
    private fun checkKeystoreAttestation(): DetectionResult {
        return try {
            val keyAlias = "anycheck_attest_${System.currentTimeMillis()}"
            val keyPairGenerator = java.security.KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
            )
            val spec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setKeySize(2048)
                .build()
            keyPairGenerator.initialize(spec)
            keyPairGenerator.generateKeyPair()

            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val privateKey = keyStore.getKey(keyAlias, null) as java.security.PrivateKey

            val isHardwareBacked = runCatching {
                val factory = java.security.KeyFactory.getInstance(
                    privateKey.algorithm, "AndroidKeyStore"
                )
                val info = factory.getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                        info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
                } else {
                    @Suppress("DEPRECATION")
                    info.isInsideSecureHardware
                }
            }.getOrDefault(false)

            runCatching { keyStore.deleteEntry(keyAlias) }

            if (isHardwareBacked) {
                DetectionResult(
                    id = "keystore_attestation",
                    name = context.getString(R.string.chk_keystore_attestation_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_keystore_attestation_desc_nd),
                    detailedReason = context.getString(R.string.chk_keystore_attestation_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed),
                    technicalDetail = "hardware_backed=true sdk=${Build.VERSION.SDK_INT}"
                )
            } else {
                DetectionResult(
                    id = "keystore_attestation",
                    name = context.getString(R.string.chk_keystore_attestation_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = context.getString(R.string.chk_keystore_attestation_desc),
                    detailedReason = context.getString(R.string.chk_keystore_attestation_reason),
                    solution = context.getString(R.string.chk_keystore_attestation_solution),
                    technicalDetail = "hardware_backed=false sdk=${Build.VERSION.SDK_INT}"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "keystore_attestation",
                name = context.getString(R.string.chk_keystore_attestation_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_keystore_attestation_desc_error),
                detailedReason = context.getString(R.string.chk_keystore_attestation_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 4: Suspicious root daemon processes
    // Scans /proc cmdlines for known root-framework daemon names.
    // These processes are strong indicators of active root frameworks
    // even when file-system artifacts have been hidden by Magisk/KSU.
    // ----------------------------------------------------------------
    private fun checkSuspiciousRootDaemons(): DetectionResult {
        val suspiciousNames = listOf(
            "magiskd",                        // Magisk daemon
            "magisk",                         // Magisk manager / init script
            "lspd",                           // LSPosed (Xposed) framework daemon
            "ksud",                           // KernelSU daemon
            "zygiskd",                        // Zygisk companion daemon
            "zygisk",                         // Zygisk loader
            "riru",                           // Riru framework
            "rirud",                          // Riru daemon
            "apd",                            // APatch daemon
            "suingod",                        // Legacy su daemon
            "su_daemon",                      // Generic su daemon
            "superuser",                      // Superuser app daemon
            "com.noshufou.android.su",        // Superuser (classic)
            "com.koushikdutta.superuser",     // Koush superuser
            "eu.chainfire.supersu"            // SuperSU
        )

        val foundProcesses = mutableListOf<String>()
        return try {
            val procDir = File("/proc")
            procDir.listFiles { _, name -> name.all { it.isDigit() } }?.forEach { pidDir ->
                run {
                    try {
                        val cmdline = File(pidDir, "cmdline")
                            .readText()
                            .replace("\u0000", " ")
                            .trim()
                        if (cmdline.isNotEmpty()) {
                            val procName = cmdline.substringAfterLast("/").substringBefore(" ")
                            for (suspect in suspiciousNames) {
                                if (procName.equals(suspect, ignoreCase = true) ||
                                    cmdline.contains("/$suspect", ignoreCase = true) ||
                                    cmdline.startsWith(suspect, ignoreCase = true)
                                ) {
                                    val entry = "$suspect (pid=${pidDir.name})"
                                    if (!foundProcesses.contains(entry)) foundProcesses.add(entry)
                                    break
                                }
                            }
                        }
                    } catch (_: Exception) {}
                }
            }

            if (foundProcesses.isNotEmpty()) {
                DetectionResult(
                    id = "suspicious_root_daemons",
                    name = context.getString(R.string.chk_suspicious_root_daemons_name),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_suspicious_root_daemons_desc),
                    detailedReason = context.getString(R.string.chk_suspicious_root_daemons_reason, foundProcesses.joinToString(", ")),
                    solution = context.getString(R.string.chk_suspicious_root_daemons_solution),
                    technicalDetail = "Processes: ${foundProcesses.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "suspicious_root_daemons",
                    name = context.getString(R.string.chk_suspicious_root_daemons_name_nd),
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = context.getString(R.string.chk_suspicious_root_daemons_desc_nd),
                    detailedReason = context.getString(R.string.chk_suspicious_root_daemons_reason_nd),
                    solution = context.getString(R.string.chk_no_action_needed)
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "suspicious_root_daemons",
                name = context.getString(R.string.chk_suspicious_root_daemons_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_suspicious_root_daemons_desc_error),
                detailedReason = context.getString(R.string.chk_suspicious_root_daemons_reason_error, e.message ?: ""),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 5: System property tampering detection
    //
    // Detects Magisk resetprop and build.prop modifications by:
    //   a) Comparing Build.TAGS (baked in at app load, cannot be changed by resetprop)
    //      against live getprop ro.build.tags
    //   b) Comparing Build.VERSION.SECURITY_PATCH against live getprop value
    //   c) Checking ro.build.fingerprint vs ro.product.device consistency
    //   d) Flagging ro.secure=0 / ro.debuggable=1 on a "user" build
    //   e) Checking for Magisk-specific properties and resetprop binary
    // ----------------------------------------------------------------
    private fun checkPropTampering(): DetectionResult {
        val issues = mutableListOf<String>()

        val buildType = getSystemProperty("ro.build.type")

        // --- (a) Build.TAGS cannot be changed by resetprop after the JVM has started ---
        val buildTagsLive = getSystemProperty("ro.build.tags")
        val buildTagsStatic = Build.TAGS ?: ""
        if (buildTagsLive.isNotEmpty() && buildTagsStatic.isNotEmpty() &&
            buildTagsLive != buildTagsStatic
        ) {
            issues.add(
                "ro.build.tags mismatch: JVM-static='$buildTagsStatic' vs live='$buildTagsLive' " +
                    "(resetprop used after boot)"
            )
        }

        // --- (b) Security patch date comparison ---
        val securityPatchLive = getSystemProperty("ro.build.version.security_patch")
        val securityPatchStatic = Build.VERSION.SECURITY_PATCH
        if (securityPatchLive.isNotEmpty() && securityPatchStatic.isNotEmpty() &&
            securityPatchLive != securityPatchStatic
        ) {
            issues.add(
                "Security patch mismatch: JVM-static='$securityPatchStatic' vs live='$securityPatchLive'"
            )
        }

        // --- (c) Fingerprint vs device name cross-check ---
        val fingerprint = getSystemProperty("ro.build.fingerprint")
        val buildDevice = getSystemProperty("ro.product.device")
        if (fingerprint.isNotEmpty() && buildDevice.isNotEmpty() &&
            !fingerprint.lowercase().contains(buildDevice.lowercase())
        ) {
            issues.add(
                "ro.product.device='$buildDevice' not present in fingerprint='$fingerprint' " +
                    "(fingerprint may be spoofed)"
            )
        }

        // --- (d) Security props vs build type ---
        if (buildType == "user" || buildType.isEmpty()) {
            if (getSystemProperty("ro.secure") == "0") {
                issues.add("ro.secure=0 on user build (modified by root framework)")
            }
            if (getSystemProperty("ro.debuggable") == "1") {
                issues.add("ro.debuggable=1 on user build (modified by root framework)")
            }
        }

        // --- (e) Magisk-specific properties ---
        val magiskVersion = getSystemProperty("ro.magisk.version")
        val magiskRevision = getSystemProperty("ro.magisk.revision")
        if (magiskVersion.isNotEmpty()) issues.add("ro.magisk.version=$magiskVersion (Magisk prop found)")
        if (magiskRevision.isNotEmpty()) issues.add("ro.magisk.revision=$magiskRevision (Magisk prop found)")

        // --- (f) resetprop binary presence ---
        val resetpropPaths = listOf(
            "/data/adb/magisk/resetprop",
            "/data/adb/magisk/bin/resetprop",
            "/sbin/resetprop",
            "/sbin/.magisk/bin/resetprop"
        )
        resetpropPaths.forEach { path ->
            if (File(path).exists()) issues.add("resetprop binary at $path")
        }

        return if (issues.isNotEmpty()) {
            DetectionResult(
                id = "prop_tampering",
                name = context.getString(R.string.chk_prop_tampering_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_prop_tampering_desc),
                detailedReason = context.getString(R.string.chk_prop_tampering_reason, issues.joinToString("; ")),
                solution = context.getString(R.string.chk_prop_tampering_solution),
                technicalDetail = "Issues: ${issues.joinToString(" | ")}"
            )
        } else {
            DetectionResult(
                id = "prop_tampering",
                name = context.getString(R.string.chk_prop_tampering_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_prop_tampering_desc_nd),
                detailedReason = context.getString(R.string.chk_prop_tampering_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 6: Extended su binary scan
    // Complements existing su_binary (GenericRootDetector) and
    // su_command (AdvancedRootDetector) with a broader path list
    // and PATH-based discovery via `which su`.
    // ----------------------------------------------------------------
    private fun checkSuExtended(): DetectionResult {
        val suPaths = listOf(
            // Traditional root locations
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/vendor/bin/su", "/system/usr/we-need-root/su",
            "/system/app/Superuser.apk",
            // Magisk variants
            "/sbin/.magisk/bin/su", "/dev/.magisk/su",
            "/data/adb/su",
            "/data/adb/magisk/busybox",
            // KernelSU
            "/data/adb/ksud",
            // APatch
            "/data/adb/apd",
            // SuperSU / daemonsu
            "/system/xbin/daemonsu", "/system/su",
            "/system/bin/.ext/su", "/system/bin/failsafe/su",
            "/system/lib/libsuperuser.so",
            // Common PATH locations
            "/usr/bin/su", "/usr/sbin/su",
            // BusyBox with su applet
            "/system/xbin/busybox", "/system/bin/busybox"
        )

        val foundPaths = mutableListOf<String>()
        suPaths.forEach { path ->
            if (File(path).exists()) foundPaths.add(path)
        }

        // PATH-based discovery via `which su`
        val whichResult = runCatching {
            val proc = Runtime.getRuntime().exec(arrayOf("which", "su"))
            proc.inputStream.bufferedReader().readLine()?.trim() ?: ""
        }.getOrDefault("")
        if (whichResult.isNotEmpty() && !foundPaths.contains(whichResult)) {
            foundPaths.add("$whichResult (via PATH)")
        }

        // Try `su --version` to check if su responds without needing to grant root
        val suResponds = runCatching {
            val proc = Runtime.getRuntime().exec(arrayOf("su", "--version"))
            proc.waitFor()
            val out = proc.inputStream.bufferedReader().readText().trim()
            val err = proc.errorStream.bufferedReader().readText().trim()
            out.isNotEmpty() || err.isNotEmpty()
        }.getOrDefault(false)
        if (suResponds && foundPaths.none { it.contains("via PATH") }) {
            foundPaths.add("su responds to --version via PATH")
        }

        return if (foundPaths.isNotEmpty()) {
            DetectionResult(
                id = "su_extended_paths",
                name = context.getString(R.string.chk_su_extended_paths_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_su_extended_paths_desc),
                detailedReason = context.getString(R.string.chk_su_extended_paths_reason, foundPaths.joinToString(", ")),
                solution = context.getString(R.string.chk_su_extended_paths_solution),
                technicalDetail = "Found: ${foundPaths.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "su_extended_paths",
                name = context.getString(R.string.chk_su_extended_paths_name_nd),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_su_extended_paths_desc_nd),
                detailedReason = context.getString(R.string.chk_su_extended_paths_reason_nd, suPaths.size),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // ----------------------------------------------------------------
    // Check 7: Snapdragon 8 Gen 2 – 8 Elite security patch check
    //
    // Devices with a Snapdragon SoC in the SM8550 (8 Gen 2) – SM8750 (8 Elite)
    // range are affected by a critical privilege-escalation vulnerability.
    // The fix is included in the 2026-03-01 security patch level.
    // Devices in this range running an older patch level are flagged CRITICAL.
    // ----------------------------------------------------------------
    private fun checkSnapdragonSecurityPatch(): DetectionResult {
        val requiredPatch = "2026-03-01"

        // Read SoC identifiers from multiple properties for broad OEM coverage.
        val socModel      = getSystemProperty("ro.soc.model")       // e.g. "SM8650"
        val boardPlatform = getSystemProperty("ro.board.platform")   // e.g. "pineapple"
        val chipName      = getSystemProperty("ro.chipname")         // e.g. "SM8550"
        val hardware      = getSystemProperty("ro.hardware")         // e.g. "kalama"

        // Affected SoC model strings (Snapdragon 8 Gen 2 → 8 Elite)
        val affectedSocModels = listOf(
            "SM8550",   // Snapdragon 8 Gen 2
            "SM8635",   // Snapdragon 8s Gen 3
            "SM8650",   // Snapdragon 8 Gen 3
            "SM8750"    // Snapdragon 8 Elite
        )

        // Corresponding platform/hardware codenames used on AOSP/OEM builds
        val affectedPlatforms = listOf(
            "kalama",    // SM8550
            "kailua",    // SM8635
            "pineapple", // SM8650
            "sun"        // SM8750
        )

        val isAffected =
            affectedSocModels.any { model ->
                socModel.contains(model, ignoreCase = true) ||
                    chipName.contains(model, ignoreCase = true)
            } || affectedPlatforms.any { platform ->
                boardPlatform.contains(platform, ignoreCase = true) ||
                    hardware.contains(platform, ignoreCase = true)
            }

        if (!isAffected) {
            return DetectionResult(
                id = "snapdragon_security_patch",
                name = context.getString(R.string.chk_snapdragon_patch_name_na),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_snapdragon_patch_desc_na),
                detailedReason = context.getString(R.string.chk_snapdragon_patch_reason_na),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "soc=$socModel platform=$boardPlatform chipname=$chipName hardware=$hardware"
            )
        }

        // Lexicographic comparison is valid for ISO-8601 "yyyy-MM-dd" strings.
        val currentPatch = Build.VERSION.SECURITY_PATCH
        val socDisplay = socModel.takeIf { it.isNotEmpty() }
            ?: boardPlatform.takeIf { it.isNotEmpty() }
            ?: chipName.takeIf { it.isNotEmpty() }
            ?: hardware

        return if (currentPatch < requiredPatch) {
            DetectionResult(
                id = "snapdragon_security_patch",
                name = context.getString(R.string.chk_snapdragon_patch_name),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_snapdragon_patch_desc),
                detailedReason = context.getString(
                    R.string.chk_snapdragon_patch_reason,
                    socDisplay, currentPatch, requiredPatch
                ),
                solution = context.getString(R.string.chk_snapdragon_patch_solution),
                technicalDetail = "SoC=$socDisplay patch=$currentPatch required=$requiredPatch"
            )
        } else {
            DetectionResult(
                id = "snapdragon_security_patch",
                name = context.getString(R.string.chk_snapdragon_patch_name_ok),
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_snapdragon_patch_desc_ok),
                detailedReason = context.getString(
                    R.string.chk_snapdragon_patch_reason_ok,
                    socDisplay, currentPatch
                ),
                solution = context.getString(R.string.chk_no_action_needed),
                technicalDetail = "SoC=$socDisplay patch=$currentPatch required=$requiredPatch"
            )
        }
    }

    private fun getSystemProperty(name: String): String = try {
        val process = Runtime.getRuntime().exec(arrayOf("getprop", name))
        process.inputStream.bufferedReader().readLine()?.trim() ?: ""
    } catch (_: Exception) {
        ""
    }
}
