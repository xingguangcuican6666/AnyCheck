package com.anycheck.app.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.ShieldMoon
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.anycheck.app.DetectionUiState
import com.anycheck.app.R
import com.anycheck.app.detection.DetectionCategory
import com.anycheck.app.detection.DetectionStatus
import com.anycheck.app.detection.DetectionSummary
import com.anycheck.app.ui.components.DetectionResultCard
import com.anycheck.app.ui.theme.RiskCritical
import com.anycheck.app.ui.theme.RiskCriticalDark
import com.anycheck.app.ui.theme.RiskLow
import com.anycheck.app.ui.theme.RiskLowDark
import com.anycheck.app.ui.theme.RiskMedium
import com.anycheck.app.ui.theme.RiskMediumContainer
import com.anycheck.app.ui.theme.RiskMediumContainerDark
import com.anycheck.app.ui.theme.RiskMediumDark
import kotlinx.coroutines.launch

enum class ResultFilter {
    ALL, DETECTED, MAGISK, KERNELSU, APATCH, SU, XPOSED, ENVIRONMENT
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    uiState: DetectionUiState,
    onStartDetection: () -> Unit,
    onShowAbout: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val clipboardManager = LocalClipboardManager.current
    val resultsCopied = stringResource(R.string.results_copied)

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(24.dp)
                        )
                        Text(
                            text = stringResource(R.string.app_name),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                    }
                },
                actions = {
                    if (uiState is DetectionUiState.Complete) {
                        IconButton(onClick = {
                            val text = buildReportText(uiState.summary)
                            clipboardManager.setText(AnnotatedString(text))
                            scope.launch { snackbarHostState.showSnackbar(resultsCopied) }
                        }) {
                            Icon(Icons.Default.ContentCopy, contentDescription = stringResource(R.string.copy_results))
                        }
                    }
                    IconButton(onClick = onShowAbout) {
                        Icon(Icons.Default.Info, contentDescription = stringResource(R.string.about))
                    }
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                )
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        modifier = modifier
    ) { paddingValues ->
        AnimatedContent(
            targetState = uiState,
            transitionSpec = { fadeIn() togetherWith fadeOut() },
            label = "screen_transition",
            modifier = Modifier.padding(paddingValues)
        ) { state ->
            when (state) {
                is DetectionUiState.Idle -> IdleScreen(onStartDetection = onStartDetection)
                is DetectionUiState.Running -> RunningScreen(progress = state.progress)
                is DetectionUiState.Complete -> ResultsScreen(
                    summary = state.summary
                )
                is DetectionUiState.Error -> ErrorScreen(
                    message = state.message,
                    onRetry = onStartDetection
                )
            }
        }
    }
}

@Composable
private fun IdleScreen(onStartDetection: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.Security,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(80.dp)
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = stringResource(R.string.app_subtitle),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.app_description),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(16.dp))
        // Feature summary
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            FeatureRow(stringResource(R.string.feature_magisk))
            FeatureRow(stringResource(R.string.feature_kernelsu))
            FeatureRow(stringResource(R.string.feature_apatch))
            FeatureRow(stringResource(R.string.feature_xposed))
            FeatureRow(stringResource(R.string.feature_advanced))
            FeatureRow(stringResource(R.string.feature_extra))
            FeatureRow(stringResource(R.string.feature_rikkax))
        }
        Spacer(modifier = Modifier.height(32.dp))
        Button(
            onClick = onStartDetection,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(16.dp)
        ) {
            Icon(Icons.Default.Search, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = stringResource(R.string.start_detection),
                style = MaterialTheme.typography.titleMedium
            )
        }
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.disclaimer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline
        )
    }
}

@Composable
private fun FeatureRow(text: String) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(
            imageVector = Icons.Default.Shield,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(16.dp)
        )
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun RunningScreen(progress: String, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        CircularProgressIndicator(
            modifier = Modifier.size(64.dp),
            strokeWidth = 4.dp
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = stringResource(R.string.detecting),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Medium
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = progress,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun ErrorScreen(
    message: String,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.Warning,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.error,
            modifier = Modifier.size(64.dp)
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.detection_failed),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.error
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(24.dp))
        Button(onClick = onRetry) {
            Text(stringResource(R.string.retry))
        }
    }
}

@Composable
private fun ResultsScreen(
    summary: DetectionSummary,
    modifier: Modifier = Modifier
) {
    var activeFilter by remember { mutableStateOf(ResultFilter.ALL) }

    // Hoist expanded state here so it persists when items scroll off screen.
    // Keys are result IDs; default (absent) means expanded only for DETECTED items.
    val expandedMap = remember { mutableStateMapOf<String, Boolean>() }

    val filteredResults = remember(activeFilter, summary.results) {
        when (activeFilter) {
            ResultFilter.ALL -> summary.results
            ResultFilter.DETECTED -> summary.results.filter { it.status == DetectionStatus.DETECTED }
            ResultFilter.MAGISK -> summary.results.filter { it.category == DetectionCategory.MAGISK }
            ResultFilter.KERNELSU -> summary.results.filter { it.category == DetectionCategory.KERNELSU }
            ResultFilter.APATCH -> summary.results.filter { it.category == DetectionCategory.APATCH }
            ResultFilter.SU -> summary.results.filter { it.category == DetectionCategory.SU_BINARY }
            ResultFilter.XPOSED -> summary.results.filter { it.category == DetectionCategory.XPOSED }
            ResultFilter.ENVIRONMENT -> summary.results.filter { it.category == DetectionCategory.ENVIRONMENT }
        }
    }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // Summary card
        item {
            SummaryCard(summary = summary, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
        }

        // Framework status row
        item {
            FrameworkStatusRow(
                summary = summary,
                modifier = Modifier.padding(horizontal = 16.dp)
            )
        }

        // Filter chips
        item {
            LazyRow(
                contentPadding = PaddingValues(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(ResultFilter.entries) { filter ->
                    val count = when (filter) {
                        ResultFilter.ALL -> summary.results.size
                        ResultFilter.DETECTED -> summary.detectedCount
                        ResultFilter.MAGISK -> summary.results.count { it.category == DetectionCategory.MAGISK }
                        ResultFilter.KERNELSU -> summary.results.count { it.category == DetectionCategory.KERNELSU }
                        ResultFilter.APATCH -> summary.results.count { it.category == DetectionCategory.APATCH }
                        ResultFilter.SU -> summary.results.count { it.category == DetectionCategory.SU_BINARY }
                        ResultFilter.XPOSED -> summary.results.count { it.category == DetectionCategory.XPOSED }
                        ResultFilter.ENVIRONMENT -> summary.results.count { it.category == DetectionCategory.ENVIRONMENT }
                    }
                    val label = when (filter) {
                        ResultFilter.ALL -> stringResource(R.string.filter_all_count, count)
                        ResultFilter.DETECTED -> stringResource(R.string.filter_detected_count, count)
                        ResultFilter.MAGISK -> stringResource(R.string.filter_magisk_count, count)
                        ResultFilter.KERNELSU -> stringResource(R.string.filter_kernelsu_count, count)
                        ResultFilter.APATCH -> stringResource(R.string.filter_apatch_count, count)
                        ResultFilter.SU -> stringResource(R.string.filter_su_count, count)
                        ResultFilter.XPOSED -> stringResource(R.string.filter_xposed_count, count)
                        ResultFilter.ENVIRONMENT -> stringResource(R.string.filter_environment_count, count)
                    }
                    FilterChip(
                        selected = activeFilter == filter,
                        onClick = { activeFilter = filter },
                        label = { Text(text = label) }
                    )
                }
            }
        }

        // Results
        items(filteredResults, key = { it.id }) { result ->
            DetectionResultCard(
                result = result,
                expanded = expandedMap.getOrDefault(
                    result.id,
                    result.status == DetectionStatus.DETECTED || result.id == "emulator"
                ),
                onExpandedChange = { expanded -> expandedMap[result.id] = expanded },
                modifier = Modifier.padding(horizontal = 16.dp)
            )
        }
    }
}

@Composable
private fun SummaryCard(summary: DetectionSummary, modifier: Modifier = Modifier) {
    val overallSafe = summary.detectedCount == 0
    val possiblyRooted = !overallSafe && summary.hasMediumOnlyDetection
    val isDark = isSystemInDarkTheme()
    val riskCriticalColor = if (isDark) RiskCriticalDark else RiskCritical
    val riskMediumColor = if (isDark) RiskMediumDark else RiskMedium
    val riskMediumContainerColor = if (isDark) RiskMediumContainerDark else RiskMediumContainer
    val riskLowColor = if (isDark) RiskLowDark else RiskLow

    val containerColor = when {
        overallSafe -> MaterialTheme.colorScheme.primaryContainer
        possiblyRooted -> riskMediumContainerColor
        else -> MaterialTheme.colorScheme.errorContainer
    }
    val onContainerColor = when {
        overallSafe -> MaterialTheme.colorScheme.onPrimaryContainer
        possiblyRooted -> riskMediumColor
        else -> MaterialTheme.colorScheme.onErrorContainer
    }
    val titleText = when {
        overallSafe -> stringResource(R.string.summary_clean)
        possiblyRooted -> stringResource(R.string.summary_possibly_rooted)
        else -> stringResource(R.string.summary_detected)
    }
    val iconVector = when {
        overallSafe -> Icons.Default.ShieldMoon
        else -> Icons.Default.Warning
    }
    val iconTint = when {
        overallSafe -> MaterialTheme.colorScheme.primary
        possiblyRooted -> riskMediumColor
        else -> MaterialTheme.colorScheme.error
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor)
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = iconVector,
                    contentDescription = null,
                    tint = iconTint,
                    modifier = Modifier.size(32.dp)
                )
                Column {
                    Text(
                        text = titleText,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = onContainerColor
                    )
                    Text(
                        text = stringResource(R.string.summary_checks_run, summary.results.size),
                        style = MaterialTheme.typography.bodySmall,
                        color = onContainerColor.copy(0.7f)
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                SummaryStatItem(
                    count = summary.detectedCount,
                    label = stringResource(R.string.stat_detected),
                    color = if (summary.detectedCount > 0) riskCriticalColor else MaterialTheme.colorScheme.outline
                )
                SummaryStatItem(
                    count = summary.safeCount,
                    label = stringResource(R.string.stat_safe),
                    color = riskLowColor
                )
                SummaryStatItem(
                    count = summary.errorCount,
                    label = stringResource(R.string.stat_errors),
                    color = MaterialTheme.colorScheme.outline
                )
            }
        }
    }
}

@Composable
private fun SummaryStatItem(count: Int, label: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = color
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun FrameworkStatusRow(summary: DetectionSummary, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        FrameworkStatusChip(
            name = stringResource(R.string.cat_magisk),
            detected = summary.hasMagisk,
            modifier = Modifier.weight(1f)
        )
        FrameworkStatusChip(
            name = stringResource(R.string.cat_kernelsu),
            detected = summary.hasKernelSU,
            modifier = Modifier.weight(1f)
        )
        FrameworkStatusChip(
            name = stringResource(R.string.cat_apatch),
            detected = summary.hasAPatch,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun FrameworkStatusChip(
    name: String,
    detected: Boolean,
    modifier: Modifier = Modifier
) {
    val isDark = isSystemInDarkTheme()
    val detectedTextColor = if (isDark) RiskCriticalDark else RiskCritical
    val safeTextColor = if (isDark) RiskLowDark else RiskLow
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = if (detected)
            MaterialTheme.colorScheme.errorContainer
        else
            MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = modifier
    ) {
        Column(
            modifier = Modifier.padding(10.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = name,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = if (detected)
                    MaterialTheme.colorScheme.onErrorContainer
                else
                    MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = if (detected) stringResource(R.string.status_detected) else stringResource(R.string.status_clean),
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = if (detected) detectedTextColor else safeTextColor
            )
        }
    }
}

private fun buildReportText(summary: DetectionSummary): String {
    val sb = StringBuilder()
    sb.appendLine("=== AnyCheck Detection Report ===")
    sb.appendLine()
    sb.appendLine("Summary:")
    sb.appendLine("  Total checks: ${summary.results.size}")
    sb.appendLine("  Detected: ${summary.detectedCount}")
    sb.appendLine("  Safe: ${summary.safeCount}")
    sb.appendLine("  Errors: ${summary.errorCount}")
    sb.appendLine()
    sb.appendLine("Framework Status:")
    sb.appendLine("  Magisk: ${if (summary.hasMagisk) "DETECTED" else "Not detected"}")
    sb.appendLine("  KernelSU: ${if (summary.hasKernelSU) "DETECTED" else "Not detected"}")
    sb.appendLine("  APatch: ${if (summary.hasAPatch) "DETECTED" else "Not detected"}")
    sb.appendLine()
    sb.appendLine("Detailed Results:")
    summary.results.forEach { result ->
        sb.appendLine()
        sb.appendLine("[${result.status.name}] ${result.name}")
        sb.appendLine("  Category: ${result.category.name}")
        sb.appendLine("  Risk: ${result.riskLevel.name}")
        sb.appendLine("  Description: ${result.description}")
        if (result.status == DetectionStatus.DETECTED) {
            sb.appendLine("  Reason: ${result.detailedReason}")
            sb.appendLine("  Solution: ${result.solution}")
        }
    }
    return sb.toString()
}
