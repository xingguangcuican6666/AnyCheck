package com.anycheck.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import com.anycheck.app.ui.AboutScreen
import com.anycheck.app.ui.MainScreen
import com.anycheck.app.ui.theme.AnyCheckTheme

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AnyCheckTheme {
                val uiState by viewModel.uiState.collectAsState()
                var showAbout by rememberSaveable { mutableStateOf(false) }

                if (showAbout) {
                    AboutScreen(
                        appVersion = "1.0.4",
                        onNavigateBack = { showAbout = false }
                    )
                } else {
                    MainScreen(
                        uiState = uiState,
                        onStartDetection = viewModel::startDetection,
                        onReset = viewModel::reset,
                        onShowAbout = { showAbout = true }
                    )
                }
            }
        }
    }
}
