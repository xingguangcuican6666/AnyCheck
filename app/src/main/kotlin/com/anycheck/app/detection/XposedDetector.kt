package com.anycheck.app.detection

import android.content.Context
import android.content.pm.PackageManager
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Detects Xposed Framework, LSPosed, EdXposed, and related hooking / virtual frameworks.
 */
class XposedDetector(private val context: Context) {

    fun runAllChecks(): List<DetectionResult> = listOf(
        checkXposedPackages(),
        checkXposedFiles(),
        checkLSPosedFiles(),
        checkEdXposedFiles(),
        checkXposedBridgeClass(),
        checkXposedInStackTrace(),
        checkXposedProps(),
        checkVirtualFrameworks(),
        checkLSPosedDaemonSocket(),
        checkLSPosedDexInMaps(),
        checkLSPosedConfigFiles(),
        checkHookedMethodDetection(),
        checkLSPosedModuleScope()
    )

    /** Check 1: Xposed / LSPosed / EdXposed manager package names */
    private fun checkXposedPackages(): DetectionResult {
        val xposedPackages = listOf(
            "de.robv.android.xposed.installer",     // Original Xposed Installer
            "org.meowcat.edxposed.manager",          // EdXposed Manager
            "org.meowcat.edxposed.manager.debug",
            "com.solohsu.android.edxp.manager",      // EdXposed (legacy)
            "org.lsposed.manager",                   // LSPosed Manager
            "io.github.lsposed.manager",
            "com.lsposed.manager",
            "io.github.vvb2060.xposeddaemon",
            "io.github.luckyzyx.lsplantmod"          // LSPlant mod
        )
        val found = xposedPackages.filter { packageExists(it) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "xposed_packages",
                name = "Xposed/LSPosed Manager Detected",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Xposed framework management app installed.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "These apps manage Xposed/LSPosed/EdXposed frameworks. " +
                    "Xposed frameworks hook into any Android app or system service at runtime.",
                solution = "Uninstall via the framework manager. Flash a stock boot image to fully remove hooks from Zygote.",
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "xposed_packages",
                name = "Xposed Manager Packages",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Xposed/LSPosed manager packages found.",
                detailedReason = "No known Xposed framework manager packages are installed.",
                solution = "No action required."
            )
        }
    }

    /** Check 2: Original Xposed Framework files */
    private fun checkXposedFiles(): DetectionResult {
        val xposedFiles = listOf(
            "/system/framework/XposedBridge.jar",
            "/system/bin/app_process_xposed",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/system/xposed.prop",
            "/system/framework/xposed-framework.jar",
            "/data/data/de.robv.android.xposed.installer"
        )
        val found = xposedFiles.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "xposed_files",
                name = "Xposed Framework Files Found",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Original Xposed framework files detected.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "XposedBridge.jar is the core Xposed hooking library. " +
                    "app_process_xposed is the modified app_process binary used to bootstrap Xposed at Zygote startup.",
                solution = "Use Xposed Installer to uninstall, or manually restore the stock app_process binary.",
                technicalDetail = "Files: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "xposed_files",
                name = "Xposed Framework Files",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No original Xposed framework files found.",
                detailedReason = "No known Xposed file paths were found on this device.",
                solution = "No action required."
            )
        }
    }

    /** Check 3: LSPosed module files */
    private fun checkLSPosedFiles(): DetectionResult {
        val lsposedFiles = listOf(
            "/data/adb/modules/lsposed",
            "/data/adb/modules/zygisk_lsposed",
            "/data/adb/modules/riru_lsposed",
            "/data/adb/lspd",
            "/dev/lspd",
            "/data/misc/lspd"
        )
        val found = lsposedFiles.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "lsposed_files",
                name = "LSPosed Module Files Found",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "LSPosed framework files detected.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "LSPosed is the modern Xposed implementation for Android 8+. " +
                    "It runs as a Zygisk or Riru module and enables per-app Xposed module scoping.",
                solution = "Remove via LSPosed Manager → Uninstall, or remove the Magisk/KernelSU module.",
                technicalDetail = "Files: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "lsposed_files",
                name = "LSPosed Files",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No LSPosed files found.",
                detailedReason = "No LSPosed-specific file paths were found.",
                solution = "No action required."
            )
        }
    }

    /** Check 4: EdXposed files */
    private fun checkEdXposedFiles(): DetectionResult {
        val edxposedFiles = listOf(
            "/data/adb/modules/edxposed",
            "/data/adb/edxposed",
            "/data/misc/edxposed_cache",
            "/system/framework/edxp.jar"
        )
        val found = edxposedFiles.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "edxposed_files",
                name = "EdXposed Files Found",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "EdXposed framework files detected.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "EdXposed is an Xposed implementation for Android 8–11 running as a Riru module. " +
                    "It enables system-wide code hooks compatible with legacy Xposed modules.",
                solution = "Remove via EdXposed Manager or delete the Riru/Magisk module.",
                technicalDetail = "Files: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "edxposed_files",
                name = "EdXposed Files",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No EdXposed files found.",
                detailedReason = "No EdXposed-specific file paths were found.",
                solution = "No action required."
            )
        }
    }

    /** Check 5: Attempt to load the XposedBridge core class */
    private fun checkXposedBridgeClass(): DetectionResult {
        return try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            DetectionResult(
                id = "xposed_bridge_class",
                name = "XposedBridge Class Loaded",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "XposedBridge class is present in the classpath.",
                detailedReason = "The class 'de.robv.android.xposed.XposedBridge' was successfully loaded. " +
                    "This class is the core of the Xposed framework and is only present when " +
                    "Xposed (or a compatible fork like LSPosed/EdXposed) is active in this process.",
                solution = "Uninstall the Xposed/LSPosed/EdXposed framework.",
                technicalDetail = "Class de.robv.android.xposed.XposedBridge loaded successfully"
            )
        } catch (_: ClassNotFoundException) {
            DetectionResult(
                id = "xposed_bridge_class",
                name = "XposedBridge Class",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "XposedBridge class not found in classpath.",
                detailedReason = "de.robv.android.xposed.XposedBridge could not be loaded. Xposed is not active.",
                solution = "No action required."
            )
        } catch (e: Exception) {
            DetectionResult(
                id = "xposed_bridge_class",
                name = "XposedBridge Class",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = "Error checking for XposedBridge class.",
                detailedReason = "Class check failed: ${e.message}",
                solution = "Unable to determine."
            )
        }
    }

    /** Check 6: Xposed/LSPlant entries in exception stack trace */
    private fun checkXposedInStackTrace(): DetectionResult {
        return try {
            throw Exception("stack_probe")
        } catch (e: Exception) {
            val stackTrace = e.stackTrace.joinToString("\n") { it.toString() }
            val xposedInStack = stackTrace.contains("XposedBridge", ignoreCase = true) ||
                stackTrace.contains("de.robv.android.xposed", ignoreCase = true) ||
                stackTrace.contains("LSPlant", ignoreCase = true) ||
                stackTrace.contains("lsplant", ignoreCase = true)
            if (xposedInStack) {
                DetectionResult(
                    id = "xposed_stack",
                    name = "Xposed Hooks in Stack Trace",
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "Xposed framework detected in exception call stack.",
                    detailedReason = "Xposed/LSPlant framework entries were found in the exception stack trace. " +
                        "This confirms that Xposed is actively hooking method calls in this process.",
                    solution = "Uninstall Xposed/LSPosed framework.",
                    technicalDetail = "Stack trace contains XposedBridge or LSPlant entries"
                )
            } else {
                DetectionResult(
                    id = "xposed_stack",
                    name = "Xposed in Stack Trace",
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "No Xposed framework entries in exception stack trace.",
                    detailedReason = "Exception stack trace shows no Xposed framework methods.",
                    solution = "No action required."
                )
            }
        }
    }

    /** Check 7: Xposed-related system properties */
    private fun checkXposedProps(): DetectionResult {
        val xposedProps = listOf(
            "ro.xposed.installed",
            "ro.xposed.version",
            "persist.sys.xposed.enable"
        )
        val found = mutableListOf<String>()
        xposedProps.forEach { key ->
            val value = getSystemProperty(key)
            if (value.isNotEmpty()) found.add("$key=$value")
        }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "xposed_props",
                name = "Xposed System Properties",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Xposed-specific system properties found.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "These properties are set by the Xposed framework or its installer.",
                solution = "Properties are removed when Xposed is properly uninstalled.",
                technicalDetail = "Props: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "xposed_props",
                name = "Xposed System Properties",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No Xposed system properties found.",
                detailedReason = "No Xposed-specific system properties were detected.",
                solution = "No action required."
            )
        }
    }

    /** Check 8: Virtual app frameworks (VirtualApp, Parallel Space, etc.) */
    private fun checkVirtualFrameworks(): DetectionResult {
        val virtualFrameworks = listOf(
            "io.va.exposed",                      // VirtualApp exposed
            "com.lody.virtual",                   // VirtualApp
            "com.parallel.space.lite",            // Parallel Space Lite
            "com.lbe.parallel.intl",              // Parallel Space
            "com.excelliance.dualaid",            // Dual Space
            "com.bly.dualspace",                  // Dual Space Pro
            "me.weishu.exp",                      // WeExp
            "com.polestar.nitro",                 // Nitro virtual engine
            "com.doubleagent.android",            // Double Agent
            "com.ludashi.benchmark",
            "com.qihoo360.mobilesafe"             // 360 Safe (may use virtualization)
        )
        val found = virtualFrameworks.filter { packageExists(it) }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "virtual_frameworks",
                name = "Virtual App Framework Detected",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "Virtual app / multi-account framework detected.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "Virtual frameworks like VirtualApp and Parallel Space create virtualized Android environments. " +
                    "They can run apps in sandboxed clones and may bypass detection by running apps inside a modified container.",
                solution = "Uninstall virtual framework apps via Settings → Apps.",
                technicalDetail = "Packages: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "virtual_frameworks",
                name = "Virtual App Frameworks",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.HIGH,
                description = "No virtual app frameworks detected.",
                detailedReason = "No known virtual framework packages were found.",
                solution = "No action required."
            )
        }
    }

    /** Check 9: LSPosed daemon Unix socket in /proc/net/unix */
    private fun checkLSPosedDaemonSocket(): DetectionResult {
        val lspdSocketNames = listOf(
            "@lspd",         // LSPosed daemon abstract socket
            "lspd",
            "@lsp",
            "lsposed_daemon",
            "@dev/lspd",
            "/dev/lspd"
        )
        return try {
            val unixContent = File("/proc/net/unix").readText()
            val found = lspdSocketNames.filter { unixContent.contains(it, ignoreCase = true) }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "lsposed_socket",
                    name = "LSPosed Daemon Socket Detected",
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "LSPosed daemon Unix socket is active.",
                    detailedReason = "Found socket(s) in /proc/net/unix: ${found.joinToString(", ")}. " +
                        "LSPosed (lspd) uses a Unix domain socket for IPC between its " +
                        "daemon process and the manager app. " +
                        "The presence of this socket confirms lspd is currently running.",
                    solution = "Remove LSPosed via the LSPosed Manager app or delete the Magisk/KSU module.",
                    technicalDetail = "Sockets: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "lsposed_socket",
                    name = "LSPosed Daemon Socket",
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "No LSPosed daemon socket found.",
                    detailedReason = "No lspd socket names found in /proc/net/unix.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "lsposed_socket",
                name = "LSPosed Daemon Socket",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = "Could not read /proc/net/unix.",
                detailedReason = "Error: ${e.message}",
                solution = "Ensure /proc/net/unix is accessible."
            )
        }
    }

    /** Check 10: LSPosed / LSPlant dex or art files loaded into this process */
    private fun checkLSPosedDexInMaps(): DetectionResult {
        val lsposedFilePatterns = listOf(
            "lsposed",
            "lsplant",
            "lspd",
            "edxp",
            "xposed"
        )
        return try {
            val maps = File("/proc/self/maps").readText()
            val found = mutableListOf<String>()
            maps.lines().forEach { line ->
                val path = line.trim().split("\\s+".toRegex()).lastOrNull()?.trim() ?: return@forEach
                if (path.isEmpty() || path.startsWith("[") || path.startsWith("anon")) return@forEach
                val filename = path.substringAfterLast("/").lowercase()
                // Check for .dex, .art, .jar, .so files with lsposed-related names
                val isRelevantType = filename.endsWith(".dex") || filename.endsWith(".art") ||
                    filename.endsWith(".jar") || filename.endsWith(".so") ||
                    filename.endsWith(".odex") || filename.endsWith(".vdex")
                if (isRelevantType && lsposedFilePatterns.any { filename.contains(it) } &&
                    !found.contains(path.take(80))
                ) {
                    found.add(path.take(80))
                }
            }
            if (found.isNotEmpty()) {
                DetectionResult(
                    id = "lsposed_dex_maps",
                    name = "LSPosed Files in Process Memory",
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "LSPosed/LSPlant files are loaded into this process.",
                    detailedReason = "Found in /proc/self/maps: ${found.joinToString(", ")}. " +
                        "LSPosed injects its hook engine (LSPlant) and module DEX files " +
                        "directly into the app's process. The presence of these mapped files " +
                        "confirms that LSPosed is actively hooking this app.",
                    solution = "Remove LSPosed or disable module scoping for this app.",
                    technicalDetail = "Files: ${found.joinToString("; ")}"
                )
            } else {
                DetectionResult(
                    id = "lsposed_dex_maps",
                    name = "LSPosed Files in Process",
                    category = DetectionCategory.XPOSED,
                    status = DetectionStatus.NOT_DETECTED,
                    riskLevel = RiskLevel.CRITICAL,
                    description = "No LSPosed/LSPlant files found in process memory.",
                    detailedReason = "No LSPosed-related files were found in /proc/self/maps.",
                    solution = "No action required."
                )
            }
        } catch (e: Exception) {
            DetectionResult(
                id = "lsposed_dex_maps",
                name = "LSPosed Files in Process",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.ERROR,
                riskLevel = RiskLevel.CRITICAL,
                description = "Could not read /proc/self/maps.",
                detailedReason = "Error: ${e.message}",
                solution = "Ensure /proc/self/maps is accessible."
            )
        }
    }

    /** Check 11: LSPosed configuration / module directories on disk */
    private fun checkLSPosedConfigFiles(): DetectionResult {
        val lsposedConfigPaths = listOf(
            "/data/misc/lspd",
            "/data/misc/lspd/config.json",
            "/data/misc/lspd/modules.json",
            "/data/misc/lspd/enabled_modules.json",
            "/data/adb/lspd",
            "/data/adb/lspd/config",
            "/data/adb/modules/zygisk_lsposed/module.prop",
            "/data/adb/modules/riru_lsposed/module.prop",
            "/data/adb/modules/lsposed/module.prop",
            "/dev/lspd",
            "/data/local/lspd"
        )
        val found = lsposedConfigPaths.filter { File(it).exists() }
        return if (found.isNotEmpty()) {
            DetectionResult(
                id = "lsposed_config",
                name = "LSPosed Configuration Files Found",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "LSPosed configuration or module files detected.",
                detailedReason = "Found: ${found.joinToString(", ")}. " +
                    "LSPosed stores its daemon configuration and module scope lists in /data/misc/lspd/. " +
                    "The presence of these files confirms LSPosed is or was installed.",
                solution = "Uninstall LSPosed via the manager app or remove the Magisk/KSU module directory.",
                technicalDetail = "Paths: ${found.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "lsposed_config",
                name = "LSPosed Configuration Files",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No LSPosed configuration files found.",
                detailedReason = "No LSPosed config paths were found on disk.",
                solution = "No action required."
            )
        }
    }

    /**
     * Check 12: Hooked method detection via Java reflection.
     *
     * LSPosed (via LSPlant) hooks Java methods by replacing their ArtMethod implementation
     * pointer. When a method is hooked, its declaring class as seen via reflection will be
     * a synthetic proxy class generated by LSPlant, rather than the real declaring class.
     * We probe several well-known methods that Xposed modules commonly target.
     */
    private fun checkHookedMethodDetection(): DetectionResult {
        val hookedMethods = mutableListOf<String>()
        val methodsToCheck = listOf(
            Triple("java.lang.Object", "hashCode", emptyArray<Class<*>>()),
            Triple("java.lang.Object", "equals", arrayOf<Class<*>>(Object::class.java)),
            Triple("android.app.Application", "onCreate", emptyArray<Class<*>>()),
            Triple("android.content.pm.PackageManager", "getPackageInfo",
                arrayOf<Class<*>>(String::class.java, Int::class.javaPrimitiveType!!))
        )
        methodsToCheck.forEach { (className, methodName, params) ->
            try {
                val clazz = Class.forName(className)
                val method = clazz.getDeclaredMethod(methodName, *params)
                val declaringClass = method.declaringClass.name
                // If the declaring class name contains synthetic hook indicators, it's hooked.
                // LSPlant proxy classes typically have "$Xposed" or "XC_Method" or unusual names.
                val hookIndicators = listOf(
                    "xposed", "lsplant", "\$xc_", "hooker", "hook_",
                    "methodhook", "xc_method", "xposedbridge"
                )
                if (hookIndicators.any { declaringClass.contains(it, ignoreCase = true) }) {
                    hookedMethods.add("$className.$methodName (declared by: $declaringClass)")
                }
                // Also check via toString — hooked methods sometimes show abnormal toString
                val methodStr = method.toString().lowercase()
                if (hookIndicators.any { methodStr.contains(it) }) {
                    val entry = "$className.$methodName"
                    if (!hookedMethods.contains(entry)) hookedMethods.add(entry)
                }
            } catch (_: Exception) {}
        }

        // Additional: probe exception stack for LSPlant hook frames
        try {
            throw RuntimeException("hook_probe")
        } catch (e: RuntimeException) {
            e.stackTrace.forEach { frame ->
                val cls = frame.className.lowercase()
                val mth = frame.methodName.lowercase()
                if (cls.contains("lsplant") || cls.contains("xposedbridge") ||
                    mth.contains("invokeoriginalmethod") || cls.contains("methodhook")
                ) {
                    hookedMethods.add("StackFrame: ${frame.className}.${frame.methodName}")
                }
            }
        }

        return if (hookedMethods.isNotEmpty()) {
            DetectionResult(
                id = "hooked_methods",
                name = "Hooked Java Methods Detected",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "Java methods are hooked by LSPosed/LSPlant.",
                detailedReason = "Hooked methods detected: ${hookedMethods.take(5).joinToString(", ")}. " +
                    "LSPosed uses the LSPlant library as its ART hook engine. " +
                    "Hooked methods have their ArtMethod implementation pointer replaced, " +
                    "causing the declaring class seen via reflection to change.",
                solution = "Remove LSPosed or disable modules that hook these methods.",
                technicalDetail = hookedMethods.take(10).joinToString("; ")
            )
        } else {
            DetectionResult(
                id = "hooked_methods",
                name = "Java Method Hooks",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No Java method hooks detected via reflection.",
                detailedReason = "No LSPlant/XposedBridge hook indicators found in reflection or stack traces.",
                solution = "No action required."
            )
        }
    }

    /**
     * Check 13: LSPosed module scope — detect if any LSPosed module is scoped to this app.
     * LSPosed records module scopes in /data/misc/lspd/. If we can read a JSON config file
     * that lists our package, it confirms a module is targeting us.
     */
    private fun checkLSPosedModuleScope(): DetectionResult {
        val ourPackage = context.packageName
        val configFiles = listOf(
            "/data/misc/lspd/config.json",
            "/data/misc/lspd/modules.json",
            "/data/misc/lspd/enabled_modules.json",
            "/data/adb/lspd/config"
        )
        val matchingFiles = mutableListOf<String>()
        configFiles.forEach { path ->
            try {
                val content = File(path).readText()
                if (content.contains(ourPackage, ignoreCase = true)) {
                    matchingFiles.add(path)
                }
            } catch (_: Exception) {}
        }

        // Also try /data/misc/lspd/modules/ directory — each module may have a scope file
        try {
            val modulesDir = File("/data/misc/lspd")
            if (modulesDir.exists()) {
                modulesDir.walk().maxDepth(3).forEach { file ->
                    if (file.isFile && (file.name.endsWith(".json") || file.name.endsWith(".list"))) {
                        try {
                            if (file.readText().contains(ourPackage, ignoreCase = true)) {
                                matchingFiles.add(file.path)
                            }
                        } catch (_: Exception) {}
                    }
                }
            }
        } catch (_: Exception) {}

        return if (matchingFiles.isNotEmpty()) {
            DetectionResult(
                id = "lsposed_module_scope",
                name = "LSPosed Module Targeting This App",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "An LSPosed module is scoped to hook this application.",
                detailedReason = "Found '$ourPackage' in LSPosed scope file(s): ${matchingFiles.joinToString(", ")}. " +
                    "LSPosed records which apps each module should be injected into. " +
                    "Seeing this app's package name in the scope config confirms " +
                    "that at least one Xposed module is actively targeting this app.",
                solution = "Open LSPosed Manager and disable all modules scoped to this app.",
                technicalDetail = "Scope files: ${matchingFiles.joinToString("; ")}"
            )
        } else {
            DetectionResult(
                id = "lsposed_module_scope",
                name = "LSPosed Module Scope",
                category = DetectionCategory.XPOSED,
                status = DetectionStatus.NOT_DETECTED,
                riskLevel = RiskLevel.CRITICAL,
                description = "No LSPosed module appears to be scoped to this app.",
                detailedReason = "This app's package name was not found in any readable LSPosed scope config.",
                solution = "No action required."
            )
        }
    }

    // ---- Utilities ----

    private fun getSystemProperty(key: String): String {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
            BufferedReader(InputStreamReader(process.inputStream)).readLine()?.trim() ?: ""
        } catch (_: Exception) {
            ""
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
