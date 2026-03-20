package com.anycheck.app.detection

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Orchestrates all detection engines and produces a unified DetectionSummary.
 */
class DetectionManager(private val context: Context) {

    suspend fun runFullDetection(
        onProgress: (Int, Int, String) -> Unit = { _, _, _ -> }
    ): DetectionSummary = withContext(Dispatchers.IO) {
        val allResults = mutableListOf<DetectionResult>()

        val magiskDetector = MagiskDetector(context)
        val kernelSUDetector = KernelSUDetector(context)
        val genericDetector = GenericRootDetector(context)
        val xposedDetector = XposedDetector(context)
        val advancedDetector = AdvancedRootDetector(context)
        val extraDetector = ExtraRootDetector(context)
        val lunaDetector = LunaDetector(context)
        val revenyDetector = RevenyInspiredDetector(context)
        val rootBeerFreshDetector = RootBeerFreshDetector(context)

        val magiskChecks = magiskDetector.runAllChecks()
        onProgress(magiskChecks.size, 0, "Magisk checks complete")
        allResults.addAll(magiskChecks)

        val ksuChecks = kernelSUDetector.runAllChecks()
        onProgress(magiskChecks.size + ksuChecks.size, magiskChecks.size, "KernelSU checks complete")
        allResults.addAll(ksuChecks)

        val genericChecks = genericDetector.runAllChecks()
        val genericEnd = magiskChecks.size + ksuChecks.size + genericChecks.size
        onProgress(genericEnd, magiskChecks.size + ksuChecks.size, "Generic checks complete")
        allResults.addAll(genericChecks)

        val xposedChecks = xposedDetector.runAllChecks()
        val xposedEnd = genericEnd + xposedChecks.size
        onProgress(xposedEnd, genericEnd, "Xposed checks complete")
        allResults.addAll(xposedChecks)

        val advancedChecks = advancedDetector.runAllChecks()
        val advancedEnd = xposedEnd + advancedChecks.size
        onProgress(advancedEnd, xposedEnd, "Advanced checks complete")
        allResults.addAll(advancedChecks)

        val extraChecks = extraDetector.runAllChecks()
        val extraEnd = advancedEnd + extraChecks.size
        onProgress(extraEnd, advancedEnd, "Extra checks complete")
        allResults.addAll(extraChecks)

        val lunaChecks = lunaDetector.runAllChecks()
        val lunaEnd = extraEnd + lunaChecks.size
        onProgress(lunaEnd, extraEnd, "Luna checks complete")
        allResults.addAll(lunaChecks)

        val revenyChecks = revenyDetector.runAllChecks()
        val revenyEnd = lunaEnd + revenyChecks.size
        onProgress(revenyEnd, lunaEnd, "Reveny-inspired checks complete")
        allResults.addAll(revenyChecks)

        val rootBeerFreshChecks = rootBeerFreshDetector.runAllChecks()
        onProgress(revenyEnd + rootBeerFreshChecks.size, revenyEnd, "RootBeerFresh checks complete")
        allResults.addAll(rootBeerFreshChecks)

        // Sort by: detected first, then by risk level, then by category
        val sorted = allResults.sortedWith(
            compareBy<DetectionResult> {
                when (it.status) {
                    DetectionStatus.DETECTED -> 0
                    DetectionStatus.ERROR -> 1
                    DetectionStatus.NOT_DETECTED -> 2
                }
            }.thenBy { it.riskLevel.order }
        )

        DetectionSummary(results = sorted)
    }
}
