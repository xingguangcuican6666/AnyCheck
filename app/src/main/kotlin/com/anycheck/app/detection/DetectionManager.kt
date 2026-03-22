package com.anycheck.app.detection

import android.content.Context
import com.anycheck.app.R
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
        val ruruDetector = RuruInspiredDetector(context)
        val systemIntegrityDetector = SystemIntegrityDetector(context)

        val magiskChecks = magiskDetector.runAllChecks()
        onProgress(magiskChecks.size, 0, context.getString(R.string.progress_magisk))
        allResults.addAll(magiskChecks)

        val ksuChecks = kernelSUDetector.runAllChecks()
        onProgress(magiskChecks.size + ksuChecks.size, magiskChecks.size, context.getString(R.string.progress_kernelsu))
        allResults.addAll(ksuChecks)

        val genericChecks = genericDetector.runAllChecks()
        val genericEnd = magiskChecks.size + ksuChecks.size + genericChecks.size
        onProgress(genericEnd, magiskChecks.size + ksuChecks.size, context.getString(R.string.progress_generic))
        allResults.addAll(genericChecks)

        val xposedChecks = xposedDetector.runAllChecks()
        val xposedEnd = genericEnd + xposedChecks.size
        onProgress(xposedEnd, genericEnd, context.getString(R.string.progress_xposed))
        allResults.addAll(xposedChecks)

        val advancedChecks = advancedDetector.runAllChecks()
        val advancedEnd = xposedEnd + advancedChecks.size
        onProgress(advancedEnd, xposedEnd, context.getString(R.string.progress_advanced))
        allResults.addAll(advancedChecks)

        val extraChecks = extraDetector.runAllChecks()
        val extraEnd = advancedEnd + extraChecks.size
        onProgress(extraEnd, advancedEnd, context.getString(R.string.progress_extra))
        allResults.addAll(extraChecks)

        val lunaChecks = lunaDetector.runAllChecks()
        val lunaEnd = extraEnd + lunaChecks.size
        onProgress(lunaEnd, extraEnd, context.getString(R.string.progress_luna))
        allResults.addAll(lunaChecks)

        val revenyChecks = revenyDetector.runAllChecks()
        val revenyEnd = lunaEnd + revenyChecks.size
        onProgress(revenyEnd, lunaEnd, context.getString(R.string.progress_reveny))
        allResults.addAll(revenyChecks)

        val rootBeerFreshChecks = rootBeerFreshDetector.runAllChecks()
        val rootBeerFreshEnd = revenyEnd + rootBeerFreshChecks.size
        onProgress(rootBeerFreshEnd, revenyEnd, context.getString(R.string.progress_rootbeer))
        allResults.addAll(rootBeerFreshChecks)

        val ruruChecks = ruruDetector.runAllChecks()
        onProgress(rootBeerFreshEnd + ruruChecks.size, rootBeerFreshEnd, context.getString(R.string.progress_ruru))
        allResults.addAll(ruruChecks)

        val sysIntegrityChecks = systemIntegrityDetector.runAllChecks()
        onProgress(rootBeerFreshEnd + ruruChecks.size + sysIntegrityChecks.size, rootBeerFreshEnd + ruruChecks.size, context.getString(R.string.progress_integrity))
        allResults.addAll(sysIntegrityChecks)

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
