package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import com.anycheck.app.R
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Hunter-inspired detection engine.
 *
 * Implements detection methods inspired by the HunterRuntime project, which
 * provides an Xposed-compatible Java hook framework (RposedBridge / RC_MethodHook)
 * backed by the LSPlant ART hook engine, plus a container-runtime with IO
 * redirection and native maps-hiding (NativiEngine).
 *
 * Checks (4 total):
 *  1.  RposedBridge class presence   — Class.forName probe for HunterRuntime's
 *      Xposed-compatible API class (analogous to XposedBridge).
 *  2.  Hunter/RposedBridge packages  — PackageManager scan for HunterRuntime
 *      app and companion packages.
 *  3.  LSPlant / Hunter native props — System property probes specific to
 *      LSPlant and HunterRuntime (extend LSPosed checks from LunaDetector).
 *  4.  ELF symbol scan (native)      — Calls NativeDetector.detectElfSymbols()
 *      which parses .dynsym / .symtab of all mapped .so files directly via
 *      mmap(2) (bypasses dlsym() and GOT-level hooks).
 */
class HunterDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkRposedBridgeClass(),
        checkHunterPackages(),
        checkLsplantHunterProperties(),
        checkElfSymbolsNative()
    )

    // -------------------------------------------------------------------------
    // Check 1: RposedBridge class presence
    // HunterRuntime exposes de.robv.android.xposed.RposedBridge (not XposedBridge)
    // as its public API.  If the class is loadable the framework is injected.
    // -------------------------------------------------------------------------
    private fun checkRposedBridgeClass(): DetectionResult {
        val candidates = listOf(
            "de.robv.android.xposed.RposedBridge",
            "io.github.lsposed.lsplant.RposedBridge",
            "org.lsposed.lsplant.RposedBridge"
        )
        val found = mutableListOf<String>()
        for (cls in candidates) {
            try {
                Class.forName(cls)
                found.add(cls)
            } catch (_: ClassNotFoundException) {
                // not present — expected on clean devices
            } catch (_: Throwable) {
                // Any other exception (e.g. SecurityException) still means the
                // class loader attempted to find it; treat as informational only.
            }
        }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "hunter_rposed_bridge_class",
                name = context.getString(R.string.chk_hunter_rposed_class_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_hunter_rposed_class_desc),
                detailedReason = context.getString(R.string.chk_hunter_rposed_class_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_hunter_rposed_class_solution),
                technicalDetail = "Classes found: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "hunter_rposed_bridge_class",
                name = context.getString(R.string.chk_hunter_rposed_class_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_hunter_rposed_class_desc_nd),
                detailedReason = context.getString(R.string.chk_hunter_rposed_class_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 2: Hunter / RposedBridge installed packages
    // Scans for HunterRuntime manager app and companion packages that are not
    // covered by the existing XposedDetector package list.
    // -------------------------------------------------------------------------
    private fun checkHunterPackages(): DetectionResult {
        val packages = listOf(
            "io.github.lsposed.manager",
            "io.github.lsposed.lsplant",
            "io.github.sdklodge.hunter",
            "io.github.sdklodge.rposedbridge",
            "com.lsposed.manager",
            "org.lsposed.manager"
        )
        val pm = context.packageManager
        val found = mutableListOf<String>()
        for (pkg in packages) {
            try {
                pm.getPackageInfo(pkg, 0)
                found.add(pkg)
            } catch (_: PackageManager.NameNotFoundException) {
                // not installed
            }
        }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "hunter_packages",
                name = context.getString(R.string.chk_hunter_packages_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hunter_packages_desc),
                detailedReason = context.getString(R.string.chk_hunter_packages_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_hunter_packages_solution),
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "hunter_packages",
                name = context.getString(R.string.chk_hunter_packages_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hunter_packages_desc_nd),
                detailedReason = context.getString(R.string.chk_hunter_packages_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 3: LSPlant / HunterRuntime system properties
    // LSPlant sets several system properties that are separate from the ones
    // checked by LunaDetector (persist.lsp.api, init.svc.lspd).
    // -------------------------------------------------------------------------
    private fun checkLsplantHunterProperties(): DetectionResult {
        val props = listOf(
            "ro.lsplant.version",
            "persist.lsplant.loaded",
            "init.svc.hunter",
            "persist.hunter.api",
            "ro.hunter.version"
        )
        val found = mutableListOf<String>()
        for (prop in props) {
            val value = getSystemProperty(prop)
            if (value.isNotEmpty()) {
                found.add("$prop=$value")
            }
        }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "hunter_lsplant_props",
                name = context.getString(R.string.chk_hunter_props_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hunter_props_desc),
                detailedReason = context.getString(R.string.chk_hunter_props_reason, found.joinToString(", ")),
                solution = context.getString(R.string.chk_hunter_props_solution),
                technicalDetail = "Props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "hunter_lsplant_props",
                name = context.getString(R.string.chk_hunter_props_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = context.getString(R.string.chk_hunter_props_desc_nd),
                detailedReason = context.getString(R.string.chk_hunter_props_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    // -------------------------------------------------------------------------
    // Check 4: Native ELF symbol scan (N10)
    // Uses the Hunter-inspired ElfImg class to parse .dynsym / .symtab sections
    // of all mapped native libraries directly via mmap(2), bypassing dlsym()
    // and any GOT-level hooks installed by the frameworks themselves.
    // -------------------------------------------------------------------------
    private fun checkElfSymbolsNative(): DetectionResult {
        val findings = NativeDetector.detectElfSymbols()
        return if (findings.isNotEmpty()) {
            DetectionResult(
                id = "hunter_elf_symbols",
                name = context.getString(R.string.chk_hunter_elf_symbols_name),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_hunter_elf_symbols_desc),
                detailedReason = context.getString(R.string.chk_hunter_elf_symbols_reason, findings),
                solution = context.getString(R.string.chk_hunter_elf_symbols_solution),
                technicalDetail = findings
            )
        } else {
            DetectionResult(
                id = "hunter_elf_symbols",
                name = context.getString(R.string.chk_hunter_elf_symbols_name_nd),
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = context.getString(R.string.chk_hunter_elf_symbols_desc_nd),
                detailedReason = context.getString(R.string.chk_hunter_elf_symbols_reason_nd),
                solution = context.getString(R.string.chk_no_action_needed)
            )
        }
    }

    private fun getSystemProperty(key: String): String {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
            BufferedReader(InputStreamReader(process.inputStream)).readLine()?.trim() ?: ""
        } catch (_: Exception) {
            ""
        }
    }
}
