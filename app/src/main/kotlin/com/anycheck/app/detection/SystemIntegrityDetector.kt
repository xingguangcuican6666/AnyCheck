package com.anycheck.app.detection

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
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
        checkSuExtended()
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
                        name = "AVB Boot State",
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.NOT_DETECTED,
                        riskLevel = RiskLevel.CRITICAL,
                        description = "Verified Boot state is GREEN.",
                        detailedReason = "ro.boot.verifiedbootstate=$verifiedBootState. " +
                            "The device booted from verified, unmodified system partitions. " +
                            "This is the strongest boot integrity assurance.",
                        solution = "No action required."
                    )
                }
                verifiedBootState.equals("yellow", ignoreCase = true) -> {
                    DetectionResult(
                        id = "avb_boot_state",
                        name = "AVB Boot State: YELLOW",
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.DETECTED,
                        riskLevel = RiskLevel.HIGH,
                        description = "Verified Boot state is YELLOW (custom ROM / self-signed).",
                        detailedReason = "ro.boot.verifiedbootstate=$verifiedBootState. " +
                            "The bootloader verified the boot image against a user-installed key " +
                            "rather than a manufacturer key. This indicates a custom ROM or " +
                            "user-enrolled AVB key. The device may be running unofficial firmware.",
                        solution = "Flash official OEM firmware to restore GREEN verified boot state.",
                        technicalDetail = "verifiedbootstate=$verifiedBootState veritymode=$verityMode"
                    )
                }
                verifiedBootState.equals("orange", ignoreCase = true) -> {
                    DetectionResult(
                        id = "avb_boot_state",
                        name = "AVB Boot State: ORANGE (Unlocked)",
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.DETECTED,
                        riskLevel = RiskLevel.CRITICAL,
                        description = "Verified Boot state is ORANGE -- bootloader is UNLOCKED.",
                        detailedReason = "ro.boot.verifiedbootstate=$verifiedBootState. " +
                            "The bootloader is unlocked and no signature is enforced. " +
                            "The device can boot arbitrary unsigned images. " +
                            "This is a strong indicator of a rooted or modified device.",
                        solution = "Re-lock the bootloader via 'fastboot flashing lock' after restoring stock firmware.",
                        technicalDetail = "verifiedbootstate=$verifiedBootState flash.locked=$bootState"
                    )
                }
                verifiedBootState.equals("red", ignoreCase = true) -> {
                    DetectionResult(
                        id = "avb_boot_state",
                        name = "AVB Boot State: RED (Integrity Failure)",
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.DETECTED,
                        riskLevel = RiskLevel.CRITICAL,
                        description = "Verified Boot state is RED -- boot image verification FAILED.",
                        detailedReason = "ro.boot.verifiedbootstate=$verifiedBootState. " +
                            "The device failed to verify the integrity of the boot image. " +
                            "This may indicate a modified bootloader or corrupted system partition.",
                        solution = "Restore factory firmware via fastboot or OTA.",
                        technicalDetail = "verifiedbootstate=$verifiedBootState"
                    )
                }
                verifiedBootState.isNotEmpty() -> {
                    DetectionResult(
                        id = "avb_boot_state",
                        name = "AVB Boot State: Unknown",
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.DETECTED,
                        riskLevel = RiskLevel.HIGH,
                        description = "Unexpected Verified Boot state: $verifiedBootState.",
                        detailedReason = "ro.boot.verifiedbootstate=$verifiedBootState is not a standard value. " +
                            "Expected: green, yellow, orange, or red.",
                        solution = "Check device firmware integrity.",
                        technicalDetail = "verifiedbootstate=$verifiedBootState"
                    )
                }
                else -> {
                    DetectionResult(
                        id = "avb_boot_state",
                        name = "AVB Boot State",
                        category = DetectionCategory.SYSTEM_INTEGRITY,
                        status = DetectionStatus.NOT_DETECTED,
                        riskLevel = RiskLevel.HIGH,
                        description = "AVB state property not available.",
                        detailedReason = "ro.boot.verifiedbootstate is empty or inaccessible. " +
                            "This is normal on older devices (pre-Android 8) that do not support AVB 2.0.",
                        solution = "No action required.",
                        technicalDetail = "verifiedbootstate=(empty) veritymode=$verityMode"
                    )
                }
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "avb_boot_state",
                name = "AVB Boot State",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Could not determine AVB boot state.",
                detailedReason = "Exception reading AVB properties: ${e.message}",
                solution = "No action required."
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
                    name = "TEE Key Generation",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "AES key was generated inside secure hardware ($securityLevelStr).",
                    detailedReason = "A probe AES key was generated via AndroidKeyStore and " +
                        "KeyInfo confirms it resides in $securityLevelStr. " +
                        "This check cannot be spoofed by Magisk property hiding because it " +
                        "exercises the actual TEE subsystem via the Binder-based Keymaster/KeyMint HAL.",
                    solution = "No action required.",
                    technicalDetail = "security_level=$securityLevelStr sdk=${Build.VERSION.SDK_INT}"
                )
            } else {
                DetectionResult(
                    id = "tee_hardware_backed",
                    name = "TEE Key Generation: Software Only",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "AES key was generated in software -- no hardware TEE backing.",
                    detailedReason = "A probe AES key was generated via AndroidKeyStore but " +
                        "KeyInfo reports it was created in the software emulation layer. " +
                        "This strongly suggests the device is an emulator, or the TEE has " +
                        "been bypassed (e.g. by a Keymaster/KeyMint shim module). " +
                        "Sensitive cryptographic material is NOT protected by secure hardware.",
                    solution = "Use a real device with a hardware TEE for secure key operations.",
                    technicalDetail = "security_level=software sdk=${Build.VERSION.SDK_INT}"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "tee_hardware_backed",
                name = "TEE Key Generation",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "TEE key generation check could not be completed.",
                detailedReason = "Exception during probe key generation: ${e.message}",
                solution = "No action required."
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
                    name = "Hardware-Backed RSA Key",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "RSA-2048 key pair resides in secure hardware (TEE/StrongBox).",
                    detailedReason = "RSA-2048 key generated via AndroidKeyStore resides inside " +
                        "the Trusted Execution Environment or StrongBox HSM. " +
                        "Private key material never leaves secure hardware.",
                    solution = "No action required.",
                    technicalDetail = "hardware_backed=true sdk=${Build.VERSION.SDK_INT}"
                )
            } else {
                DetectionResult(
                    id = "keystore_attestation",
                    name = "Hardware-Backed RSA Key: Software Only",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.HIGH,
                    description = "RSA key pair is in software keystore, not secure hardware.",
                    detailedReason = "The AndroidKeyStore RSA key was generated in the software " +
                        "emulation layer rather than in a hardware TEE. This may indicate " +
                        "an emulator, a rooted device with Magisk hiding active, or a device " +
                        "that does not have a hardware-backed keystore.",
                    solution = "Use a device with hardware-backed key storage for sensitive operations.",
                    technicalDetail = "hardware_backed=false sdk=${Build.VERSION.SDK_INT}"
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "keystore_attestation",
                name = "Hardware-Backed RSA Key",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Keystore attestation check could not be completed.",
                detailedReason = "Exception during RSA key generation/inspection: ${e.message}",
                solution = "No action required."
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
            procDir.listFiles()?.forEach { pidDir ->
                if (pidDir.isDirectory && pidDir.name.all { it.isDigit() }) {
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
                    name = "Root Daemon Processes Running",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "Active root framework daemon(s) detected in process list.",
                    detailedReason = "The following root-related processes are running: " +
                        "${foundProcesses.joinToString(", ")}. " +
                        "lspd is the LSPosed/Xposed framework daemon. " +
                        "ksud is the KernelSU daemon. " +
                        "magiskd is the Magisk daemon. " +
                        "zygiskd is the Zygisk companion daemon. " +
                        "These confirm an active root framework even if file artifacts are hidden.",
                    solution = "Uninstall the root framework and reboot to stop these daemons.",
                    technicalDetail = "Processes: ${foundProcesses.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "suspicious_root_daemons",
                    name = "Root Daemon Processes",
                    category = DetectionCategory.SYSTEM_INTEGRITY,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "No known root framework daemons found in process list.",
                    detailedReason = "Scanned /proc for lspd, ksud, magiskd, zygiskd, riru, apd, " +
                        "and other known root framework daemons. None were found.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "suspicious_root_daemons",
                name = "Root Daemon Processes",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Could not scan process list.",
                detailedReason = "Exception reading /proc: ${e.message}",
                solution = "No action required."
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
                name = "System Property Tampering",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "System properties show signs of modification.",
                detailedReason = "The following property inconsistencies were detected: " +
                    issues.joinToString("; ") + ". " +
                    "Magisk resetprop can modify any system property after boot, " +
                    "but Android framework constants baked into the app JVM at launch " +
                    "cannot be changed retroactively -- a mismatch proves tampering.",
                solution = "Restore stock boot image to reset system properties to factory values.",
                technicalDetail = "Issues: ${issues.joinToString(" | ")}"
            )
        } else {
            DetectionResult(
                id = "prop_tampering",
                name = "System Property Tampering",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No system property tampering detected.",
                detailedReason = "Build.TAGS vs live ro.build.tags, security patch cross-check, " +
                    "fingerprint vs device name, and Magisk prop checks all passed. " +
                    "System properties are consistent with the stock build.",
                solution = "No action required."
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
                name = "Su Binary (Extended Scan)",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Su binary or root management files found.",
                detailedReason = "The following su-related paths were found: " +
                    "${foundPaths.joinToString(", ")}. " +
                    "Presence of a su binary is a strong indicator that the device is rooted.",
                solution = "Remove all root frameworks (Magisk, KernelSU, APatch, SuperSU) " +
                    "and restore the stock boot image.",
                technicalDetail = "Found: ${foundPaths.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "su_extended_paths",
                name = "Su Binary (Extended Scan)",
                category = DetectionCategory.SYSTEM_INTEGRITY,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No su binary or root management files found.",
                detailedReason = "Scanned ${suPaths.size} known su binary paths and checked PATH. " +
                    "No su binary was found accessible on this device.",
                solution = "No action required."
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
