package com.defenceiq.app.network

import android.util.Log
import com.defenceiq.app.data.*
import com.google.gson.Gson
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

enum class ConnectionStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR
}

/**
 * Single source of truth for laptop agent communications, state management,
 * and live alert push reception.
 */
class DefenceIqRepository(
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
) {
    private val tag = "DefenceIqRepo"
    private val gson = Gson()

    // Host & Auth credentials
    var host: String = "192.168.1.4"
        private set
    var port: Int = 8765
        private set
    var token: String = "11C6C497"
        private set

    // State flows
    private val _connectionState = MutableStateFlow(ConnectionStatus.DISCONNECTED)
    val connectionState: StateFlow<ConnectionStatus> = _connectionState.asStateFlow()

    private val _agentStatus = MutableStateFlow<AgentStatusResponse?>(null)
    val agentStatus: StateFlow<AgentStatusResponse?> = _agentStatus.asStateFlow()

    private val _incidents = MutableStateFlow<List<Incident>>(emptyList())
    val incidents: StateFlow<List<Incident>> = _incidents.asStateFlow()

    private val _quarantinedFiles = MutableStateFlow<List<QuarantinedFile>>(emptyList())
    val quarantinedFiles: StateFlow<List<QuarantinedFile>> = _quarantinedFiles.asStateFlow()

    private val _transports = MutableStateFlow<TransportsResponse?>(null)
    val transports: StateFlow<TransportsResponse?> = _transports.asStateFlow()

    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

    // Network clients
    private var apiService: DefenceIqApiService? = null
    private var okHttpClient: OkHttpClient? = null
    private var webSocket: WebSocket? = null

    init {
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BASIC
        }
        okHttpClient = OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .addInterceptor(logging)
            .build()
    }

    private fun getAuthHeader(): String = "Bearer $token"

    /**
     * Tests pairing token and starts active REST and WebSocket sessions.
     */
    suspend fun pairAndConnect(targetHost: String, targetPort: Int, pairingToken: String): Result<PairResponse> = withContext(Dispatchers.IO) {
        try {
            _connectionState.value = ConnectionStatus.CONNECTING
            host = targetHost.trim()
            port = targetPort
            token = pairingToken.trim().uppercase()

            val baseUrl = "http://$host:$port/"
            val retrofit = Retrofit.Builder()
                .baseUrl(baseUrl)
                .client(okHttpClient!!)
                .addConverterFactory(GsonConverterFactory.create(gson))
                .build()

            apiService = retrofit.create(DefenceIqApiService::class.java)

            // Test pairing endpoint
            val pairRes = apiService!!.pairDevice(PairRequest(token))
            if (!pairRes.isSuccessful || pairRes.body() == null) {
                _connectionState.value = ConnectionStatus.ERROR
                val err = "Pairing failed: HTTP ${pairRes.code()} ${pairRes.message()}"
                _lastError.value = err
                return@withContext Result.failure(Exception(err))
            }

            val pairBody = pairRes.body()!!
            _connectionState.value = ConnectionStatus.CONNECTED

            // Initial fetch of status, incidents, and quarantine vault
            refreshStatus()
            refreshIncidents()
            refreshQuarantine()

            // Establish real-time WebSocket connection
            connectWebSocket()

            Result.success(pairBody)
        } catch (e: Exception) {
            _connectionState.value = ConnectionStatus.ERROR
            _lastError.value = e.message
            Log.e(tag, "Pairing exception: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Connects to the laptop's live WebSocket alert stream.
     */
    fun connectWebSocket() {
        webSocket?.cancel()
        val wsUrl = "ws://$host:$port/ws/alerts?token=$token"
        val request = Request.Builder().url(wsUrl).build()

        val listener = AlertsWebSocketListener(
            gson = gson,
            onConnected = {
                _connectionState.value = ConnectionStatus.CONNECTED
            },
            onDisconnected = { reason ->
                Log.w(tag, "WebSocket disconnected: $reason")
            },
            onFrameReceived = { frame ->
                handleWebSocketFrame(frame)
            },
            onError = { t ->
                Log.e(tag, "WebSocket error: ${t.message}")
            }
        )

        webSocket = okHttpClient?.newWebSocket(request, listener)
    }

    private fun handleWebSocketFrame(frame: WebSocketAlertFrame) {
        scope.launch {
            when (frame.type) {
                "incident" -> {
                    frame.incident?.let { newInc ->
                        val current = _incidents.value.toMutableList()
                        val existingIndex = current.indexOfFirst { it.incidentId == newInc.incidentId }
                        if (existingIndex >= 0) {
                            current[existingIndex] = newInc
                        } else {
                            current.add(0, newInc)
                        }
                        _incidents.value = current
                    }
                    refreshStatus()
                }
                "incident_rollback" -> {
                    refreshIncidents()
                    refreshStatus()
                }
                "protection_level_changed" -> {
                    refreshStatus()
                }
                "quarantine_restored" -> {
                    refreshQuarantine()
                    refreshStatus()
                }
                else -> {
                    Log.d(tag, "Received unhandled frame type: ${frame.type}")
                }
            }
        }
    }

    /**
     * Refreshes laptop protection status, active sockets, and telemetry statistics.
     */
    suspend fun refreshStatus(): Result<AgentStatusResponse> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.getStatus(getAuthHeader())
            if (res.isSuccessful && res.body() != null) {
                _agentStatus.value = res.body()
                Result.success(res.body()!!)
            } else {
                Result.failure(Exception("Status query failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Refreshes incident list with complete explainability breakdowns.
     */
    suspend fun refreshIncidents(): Result<List<Incident>> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.getIncidents(getAuthHeader(), limit = 100)
            if (res.isSuccessful && res.body() != null) {
                _incidents.value = res.body()!!.incidents
                Result.success(res.body()!!.incidents)
            } else {
                Result.failure(Exception("Incidents query failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Triggers one-tap rollback of containment actions for an incident.
     */
    suspend fun rollbackIncident(incidentId: String): Result<RollbackResponse> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.rollbackIncident(getAuthHeader(), incidentId)
            if (res.isSuccessful && res.body() != null) {
                refreshIncidents()
                refreshStatus()
                Result.success(res.body()!!)
            } else {
                Result.failure(Exception("Rollback failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Updates the active protection level (basic, balanced, maximum).
     */
    suspend fun setProtectionLevel(level: String): Result<Boolean> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.updateProtectionLevel(getAuthHeader(), ProtectionLevelRequest(level))
            if (res.isSuccessful) {
                refreshStatus()
                Result.success(true)
            } else {
                Result.failure(Exception("Level change failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Refreshes quarantine vault listing.
     */
    suspend fun refreshQuarantine(): Result<List<QuarantinedFile>> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.getQuarantine(getAuthHeader())
            if (res.isSuccessful && res.body() != null) {
                _quarantinedFiles.value = res.body()!!.quarantinedFiles
                Result.success(res.body()!!.quarantinedFiles)
            } else {
                Result.failure(Exception("Quarantine query failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Restores a quarantined file back to original location.
     */
    suspend fun restoreQuarantinedFile(quarantineId: String): Result<Boolean> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.restoreQuarantinedFile(getAuthHeader(), quarantineId)
            if (res.isSuccessful) {
                refreshQuarantine()
                Result.success(true)
            } else {
                Result.failure(Exception("Restore failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Queries connectivity status across LAN, USB ADB, Bluetooth, and Cloud Relay.
     */
    suspend fun refreshTransports(): Result<TransportsResponse> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.getTransports(getAuthHeader())
            if (res.isSuccessful && res.body() != null) {
                _transports.value = res.body()!!
                Result.success(res.body()!!)
            } else {
                Result.failure(Exception("Transports query failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun disconnect() {
        webSocket?.close(1000, "User disconnected")
        webSocket = null
        _connectionState.value = ConnectionStatus.DISCONNECTED
    }
}
