package com.anycheck.app.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.anycheck.app.R
import com.anycheck.app.detection.DetectionCategory
import com.anycheck.app.detection.DetectionResult
import com.anycheck.app.detection.DetectionStatus
import com.anycheck.app.detection.RiskLevel
import com.anycheck.app.ui.theme.RiskCritical
import com.anycheck.app.ui.theme.RiskCriticalContainer
import com.anycheck.app.ui.theme.RiskCriticalContainerDark
import com.anycheck.app.ui.theme.RiskCriticalDark
import com.anycheck.app.ui.theme.RiskHigh
import com.anycheck.app.ui.theme.RiskHighContainer
import com.anycheck.app.ui.theme.RiskHighContainerDark
import com.anycheck.app.ui.theme.RiskHighDark
import com.anycheck.app.ui.theme.RiskInfo
import com.anycheck.app.ui.theme.RiskInfoContainer
import com.anycheck.app.ui.theme.RiskInfoContainerDark
import com.anycheck.app.ui.theme.RiskInfoDark
import com.anycheck.app.ui.theme.RiskLow
import com.anycheck.app.ui.theme.RiskLowContainer
import com.anycheck.app.ui.theme.RiskLowContainerDark
import com.anycheck.app.ui.theme.RiskLowDark
import com.anycheck.app.ui.theme.RiskMedium
import com.anycheck.app.ui.theme.RiskMediumContainer
import com.anycheck.app.ui.theme.RiskMediumContainerDark
import com.anycheck.app.ui.theme.RiskMediumDark
import com.anycheck.app.ui.theme.StatusDetected
import com.anycheck.app.ui.theme.StatusDetectedDark
import com.anycheck.app.ui.theme.StatusError
import com.anycheck.app.ui.theme.StatusErrorDark
import com.anycheck.app.ui.theme.StatusNotDetected
import com.anycheck.app.ui.theme.StatusNotDetectedDark

@Composable
fun DetectionResultCard(
    result: DetectionResult,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {

    val (riskColor, riskContainerColor) = riskColors(result.riskLevel)
    val (statusColor, statusIcon) = statusStyle(result.status)
    val cardContainerColor = when (result.status) {
        DetectionStatus.DETECTED -> riskContainerColor
        DetectionStatus.NOT_DETECTED -> MaterialTheme.colorScheme.surfaceContainerLow
        DetectionStatus.ERROR -> MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .animateContentSize()
            .clickable { onExpandedChange(!expanded) },
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = cardContainerColor
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = if (result.status == DetectionStatus.DETECTED) 2.dp else 0.dp
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Header row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Status icon
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(statusColor.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = statusIcon,
                        contentDescription = result.status.name,
                        tint = statusColor,
                        modifier = Modifier.size(22.dp)
                    )
                }

                // Name and category
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = result.name,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = if (result.status == DetectionStatus.DETECTED) FontWeight.Bold else FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CategoryBadge(category = result.category)
                        RiskBadge(riskLevel = result.riskLevel, color = riskColor)
                    }
                }

                // Expand/collapse icon
                Icon(
                    imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = if (expanded) stringResource(R.string.collapse) else stringResource(R.string.expand),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp)
                )
            }

            // Brief description always visible
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = result.description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // Expanded details
            AnimatedVisibility(
                visible = expanded,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Column {
                    Spacer(modifier = Modifier.height(12.dp))
                    HorizontalDivider(
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )
                    Spacer(modifier = Modifier.height(12.dp))

                    // Detailed reason
                    DetailSection(
                        icon = Icons.Default.Info,
                        title = stringResource(R.string.detail_reason),
                        content = result.detailedReason,
                        iconTint = MaterialTheme.colorScheme.primary
                    )

                    if (result.status == DetectionStatus.DETECTED) {
                        Spacer(modifier = Modifier.height(10.dp))
                        // Solution
                        DetailSection(
                            icon = Icons.AutoMirrored.Filled.HelpOutline,
                            title = stringResource(R.string.detail_solution),
                            content = result.solution,
                            iconTint = if (isSystemInDarkTheme()) RiskLowDark else RiskLow
                        )
                    }

                    if (result.technicalDetail.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        // Technical details
                        TechnicalDetailBox(detail = result.technicalDetail)
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailSection(
    icon: ImageVector,
    title: String,
    content: String,
    iconTint: Color,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = icon,
            contentDescription = title,
            tint = iconTint,
            modifier = Modifier
                .size(16.dp)
                .padding(top = 2.dp)
        )
        Column {
            Text(
                text = title,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = content,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                lineHeight = 18.sp
            )
        }
    }
}

@Composable
private fun TechnicalDetailBox(detail: String, modifier: Modifier = Modifier) {
    Column(modifier = modifier) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.BugReport,
                contentDescription = stringResource(R.string.detail_technical),
                tint = MaterialTheme.colorScheme.outline,
                modifier = Modifier.size(16.dp)
            )
            Text(
                text = stringResource(R.string.detail_technical),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Surface(
            shape = RoundedCornerShape(8.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHighest.copy(alpha = 0.7f),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = detail,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                ),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp)
            )
        }
    }
}

@Composable
fun CategoryBadge(category: DetectionCategory, modifier: Modifier = Modifier) {
    val isDark = isSystemInDarkTheme()
    val text = when (category) {
        DetectionCategory.MAGISK -> stringResource(R.string.cat_magisk)
        DetectionCategory.KERNELSU -> stringResource(R.string.cat_kernelsu)
        DetectionCategory.APATCH -> stringResource(R.string.cat_apatch)
        DetectionCategory.SU_BINARY -> stringResource(R.string.cat_su_binary)
        DetectionCategory.ROOT_MANAGEMENT -> stringResource(R.string.cat_root)
        DetectionCategory.XPOSED -> stringResource(R.string.cat_xposed)
        DetectionCategory.SYSTEM_INTEGRITY -> stringResource(R.string.cat_system)
        DetectionCategory.ADB_DEBUG -> stringResource(R.string.cat_adb_debug)
        DetectionCategory.FRIDA -> stringResource(R.string.cat_frida)
        DetectionCategory.ENVIRONMENT -> stringResource(R.string.cat_environment)
        DetectionCategory.NETWORK -> stringResource(R.string.cat_network)
    }
    val (lightColor, darkColor) = when (category) {
        DetectionCategory.MAGISK -> Color(0xFF4A55A2) to Color(0xFFB8C3FF)
        DetectionCategory.KERNELSU -> Color(0xFF00796B) to Color(0xFF80CBC4)
        DetectionCategory.APATCH -> Color(0xFF6A1B9A) to Color(0xFFCE93D8)
        DetectionCategory.SU_BINARY -> Color(0xFFBF360C) to Color(0xFFFFAB91)
        DetectionCategory.ROOT_MANAGEMENT -> Color(0xFF37474F) to Color(0xFF90A4AE)
        DetectionCategory.XPOSED -> Color(0xFFC62828) to Color(0xFFEF9A9A)
        DetectionCategory.SYSTEM_INTEGRITY -> Color(0xFF0277BD) to Color(0xFF81D4FA)
        DetectionCategory.ADB_DEBUG -> Color(0xFF33691E) to Color(0xFFAED581)
        DetectionCategory.FRIDA -> Color(0xFF4E342E) to Color(0xFFBCAAA4)
        DetectionCategory.ENVIRONMENT -> Color(0xFF00695C) to Color(0xFF80CBC4)
        DetectionCategory.NETWORK -> Color(0xFF1565C0) to Color(0xFF90CAF9)
    }
    val color = if (isDark) darkColor else lightColor
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = color.copy(alpha = if (isDark) 0.20f else 0.15f),
        modifier = modifier
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = color,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

@Composable
fun RiskBadge(riskLevel: RiskLevel, color: Color, modifier: Modifier = Modifier) {
    val text = when (riskLevel) {
        RiskLevel.CRITICAL -> stringResource(R.string.risk_critical)
        RiskLevel.HIGH -> stringResource(R.string.risk_high)
        RiskLevel.MEDIUM -> stringResource(R.string.risk_medium)
        RiskLevel.LOW -> stringResource(R.string.risk_low)
        RiskLevel.INFO -> stringResource(R.string.risk_info)
    }
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = color.copy(alpha = 0.15f),
        modifier = modifier
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = color,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

@Composable
fun riskColors(riskLevel: RiskLevel): Pair<Color, Color> {
    val isDark = isSystemInDarkTheme()
    return when (riskLevel) {
        RiskLevel.CRITICAL -> if (isDark) RiskCriticalDark to RiskCriticalContainerDark else RiskCritical to RiskCriticalContainer
        RiskLevel.HIGH -> if (isDark) RiskHighDark to RiskHighContainerDark else RiskHigh to RiskHighContainer
        RiskLevel.MEDIUM -> if (isDark) RiskMediumDark to RiskMediumContainerDark else RiskMedium to RiskMediumContainer
        RiskLevel.LOW -> if (isDark) RiskLowDark to RiskLowContainerDark else RiskLow to RiskLowContainer
        RiskLevel.INFO -> if (isDark) RiskInfoDark to RiskInfoContainerDark else RiskInfo to RiskInfoContainer
    }
}

@Composable
fun statusStyle(status: DetectionStatus): Pair<Color, ImageVector> {
    val isDark = isSystemInDarkTheme()
    return when (status) {
        DetectionStatus.DETECTED -> (if (isDark) StatusDetectedDark else StatusDetected) to Icons.Default.Error
        DetectionStatus.NOT_DETECTED -> (if (isDark) StatusNotDetectedDark else StatusNotDetected) to Icons.Default.CheckCircle
        DetectionStatus.ERROR -> (if (isDark) StatusErrorDark else StatusError) to Icons.Default.Warning
    }
}
