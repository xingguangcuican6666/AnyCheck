package com.anycheck.app

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.anycheck.app.detection.DetectionManager
import com.anycheck.app.detection.DetectionSummary
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed class DetectionUiState {
    data object Idle : DetectionUiState()
    data class Running(val progress: String = "Starting...") : DetectionUiState()
    data class Complete(val summary: DetectionSummary) : DetectionUiState()
    data class Error(val message: String) : DetectionUiState()
}

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val detectionManager = DetectionManager(application)

    private val _uiState = MutableStateFlow<DetectionUiState>(DetectionUiState.Idle)
    val uiState: StateFlow<DetectionUiState> = _uiState.asStateFlow()

    fun startDetection() {
        if (_uiState.value is DetectionUiState.Running) return
        viewModelScope.launch {
            _uiState.value = DetectionUiState.Running("Initializing checks...")
            try {
                val summary = detectionManager.runFullDetection { total, completed, message ->
                    _uiState.value = DetectionUiState.Running(
                        "$message ($completed/$total)"
                    )
                }
                _uiState.value = DetectionUiState.Complete(summary)
            } catch (e: Exception) {
                _uiState.value = DetectionUiState.Error(
                    "Detection failed: ${e.message ?: "Unknown error"}"
                )
            }
        }
    }

    fun reset() {
        _uiState.value = DetectionUiState.Idle
    }
}
