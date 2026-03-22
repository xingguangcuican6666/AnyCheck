package com.anycheck.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lightbulb
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.anycheck.app.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AboutScreen(
    appVersion: String = "1.0.0",
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Text(
                        text = stringResource(R.string.about),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.navigate_back)
                        )
                    }
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                )
            )
        },
        modifier = modifier
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // App icon + name
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier.size(88.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .padding(20.dp)
                            .fillMaxSize()
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.app_name),
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = stringResource(R.string.version_format, appVersion),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // Description card
            AboutCard(
                icon = Icons.Default.Info,
                title = stringResource(R.string.about_app_title)
            ) {
                Text(
                    text = stringResource(R.string.about_app_description),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // Author & repository card
            AboutCard(
                icon = Icons.Default.Person,
                title = stringResource(R.string.about_author_title)
            ) {
                DetectionMethodRow(
                    stringResource(R.string.about_author_github_label),
                    stringResource(R.string.about_author_github_value)
                )
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                DetectionMethodRow(
                    stringResource(R.string.about_author_repo_label),
                    stringResource(R.string.about_author_repo_value)
                )
            }

            // Philosophy card
            AboutCard(
                icon = Icons.Default.Lightbulb,
                title = stringResource(R.string.about_philosophy_title)
            ) {
                Text(
                    text = stringResource(R.string.about_philosophy_content),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // Detection methods card
            AboutCard(
                icon = Icons.Default.Security,
                title = stringResource(R.string.about_detection_methods)
            ) {
                DetectionMethodRow(
                    stringResource(R.string.about_method_magisk),
                    stringResource(R.string.about_method_magisk_count)
                )
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                DetectionMethodRow(
                    stringResource(R.string.about_method_kernelsu),
                    stringResource(R.string.about_method_kernelsu_count)
                )
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                DetectionMethodRow(
                    stringResource(R.string.about_method_apatch),
                    stringResource(R.string.about_method_apatch_count)
                )
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                DetectionMethodRow(
                    stringResource(R.string.about_method_xposed),
                    stringResource(R.string.about_method_xposed_count)
                )
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                DetectionMethodRow(
                    stringResource(R.string.about_method_advanced),
                    stringResource(R.string.about_method_advanced_count)
                )
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                DetectionMethodRow(
                    stringResource(R.string.about_method_luna),
                    stringResource(R.string.about_method_luna_count)
                )
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                DetectionMethodRow(
                    stringResource(R.string.about_method_integrity),
                    stringResource(R.string.about_method_integrity_count)
                )
            }

            // Risk level explanation card
            AboutCard(
                icon = Icons.Default.BugReport,
                title = stringResource(R.string.about_risk_levels)
            ) {
                RiskLevelRow(stringResource(R.string.risk_critical), stringResource(R.string.risk_critical_desc))
                Spacer(modifier = Modifier.height(6.dp))
                RiskLevelRow(stringResource(R.string.risk_high), stringResource(R.string.risk_high_desc))
                Spacer(modifier = Modifier.height(6.dp))
                RiskLevelRow(stringResource(R.string.risk_medium), stringResource(R.string.risk_medium_desc))
                Spacer(modifier = Modifier.height(6.dp))
                RiskLevelRow(stringResource(R.string.risk_low), stringResource(R.string.risk_low_desc))
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.about_risk_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // Disclaimer
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                )
            ) {
                Text(
                    text = stringResource(R.string.disclaimer_about),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                )
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

@Composable
private fun AboutCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    content: @Composable () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
            content()
        }
    }
}

@Composable
private fun DetectionMethodRow(name: String, detail: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = name,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = detail,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun RiskLevelRow(level: String, description: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            text = "●",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary
        )
        Column {
            Text(
                text = level,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
