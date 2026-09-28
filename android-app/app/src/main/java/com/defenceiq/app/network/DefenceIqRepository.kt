package com.defenceiq.app.network

import android.content.Context
import android.util.Log
import com.defenceiq.app.data.*
import com.defenceiq.app.ui.notifications.NotificationHelper
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
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.TimeUnit

enum class ConnectionStatus(val label: String) {
    CONNECTED("Connected"),
    CONNECTING("Connecting"),
    CONNECTION_LOST("Connection Lost"),
    LAPTOP_OFFLINE("Laptop Offline"),
    DISCONNECTED("Disconnected");

    val isOnline: Boolean
        get() = this == CONNECTED
}

/**
 * Single source of truth for laptop agent communications, state management,
 * and live alert push reception.
 *
 * Supports:
 * 1. IP-Independent Cloud Relay pairing via unique token (Primary)
 * 2. Local Wi-Fi / LAN REST & WebSocket direct pairing (Secondary / Fallback)
 * 3. Bidirectional Token Pairing (Laptop -> Phone and Phone -> Laptop)
 * 4. Automatic Security Alerts for device connections, unexpected disconnects,
 *    unauthenticated attempts, and status transitions.
 * 5. Watchdog keepalive tracking with real-time last-seen updates.
 */
class DefenceIqRepository(
    private val appContext: Context? = null,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
) {
    private val tag = "DefenceIqRepo"
    private val gson = Gson()

    // Host & Auth credentials
    var host: String = "defenceiq.onrender.com"
        private set
    var port: Int = 443
        private set
    var token: String = "DIQ-FUXN-G8CE"
        private set

    // Watchdog and timing
    private var lastHeartbeatTimeMs: Long = 0L

    // Cloud Relay Client (IP-Independent)
    val cloudRelay: CloudRelayClient = CloudRelayClient(
        scope = scope,
        onThreatAlertReceived = { alert ->
            onCloudThreatAlert(alert)
        },
        onSecurityAlertReceived = { secAlert ->
            onSecurityAlert(secAlert)
        },
        onStatusReceived = { status ->
            _agentStatus.value = status
            recordHeartbeat("relay")
        }
    )

    // State flows
    private val _connectionState = MutableStateFlow(ConnectionStatus.DISCONNECTED)
    val connectionState: StateFlow<ConnectionStatus> = _connectionState.asStateFlow()

    private val _agentStatus = MutableStateFlow<AgentStatusResponse?>(null)
    val agentStatus: StateFlow<AgentStatusResponse?> = _agentStatus.asStateFlow()

    private val _incidents = MutableStateFlow<List<Incident>>(emptyList())
    val incidents: StateFlow<List<Incident>> = _incidents.asStateFlow()

    private val _securityAlerts = MutableStateFlow<List<SecurityAlert>>(emptyList())
    val securityAlerts: StateFlow<List<SecurityAlert>> = _securityAlerts.asStateFlow()

    private val _quarantinedFiles = MutableStateFlow<List<QuarantinedFile>>(emptyList())
    val quarantinedFiles: StateFlow<List<QuarantinedFile>> = _quarantinedFiles.asStateFlow()

    private val _transports = MutableStateFlow<TransportsResponse?>(null)
    val transports: StateFlow<TransportsResponse?> = _transports.asStateFlow()

    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

    private val _lastSeen = MutableStateFlow<String>("Never")
    val lastSeen: StateFlow<String> = _lastSeen.asStateFlow()

    private val _lastConnected = MutableStateFlow<String>("Never")
    val lastConnected: StateFlow<String> = _lastConnected.asStateFlow()

    // Reverse pairing token (Phone -> Laptop)
    private val _mobilePairingToken = MutableStateFlow<String?>(null)
    val mobilePairingToken: StateFlow<String?> = _mobilePairingToken.asStateFlow()

    private val _mobileTokenExpiresAt = MutableStateFlow<Long>(0L)
    val mobileTokenExpiresAt: StateFlow<Long> = _mobileTokenExpiresAt.asStateFlow()

    val pairedDevice: StateFlow<PairedDevice?> = cloudRelay.pairedDevice

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

        // Observe Cloud Relay pairedDevice state
        scope.launch {
            cloudRelay.pairedDevice.collect { dev ->
                if (dev != null) {
                    _connectionState.value = ConnectionStatus.CONNECTED
                    token = dev.token
                    recordHeartbeat("relay_handshake")
                    val nowStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
                    _lastConnected.value = dev.pairedAt.ifEmpty { nowStr }

                    // Synthesize agent status for UI if direct REST is not yet loaded
                    if (_agentStatus.value == null) {
                        _agentStatus.value = AgentStatusResponse(
                            healthState = "SECURE",
                            protectionLevel = dev.protectionLevel,
                            hostname = dev.hostname,
                            lanIp = "Relay (Global)",
                            timestamp = dev.pairedAt,
                            monitoredPidsCount = 0,
                            activeSocketsCount = 0,
                            stats = SystemStats(0, _incidents.value.size, mapOf("RED" to 0, "ORANGE" to 0), 0),
                            engines = mapOf("cloud_relay" to "active", "threat_watcher" to "active"),
                            connectionStatus = "Connected",
                            lastSeen = nowStr,
                            lastConnected = dev.pairedAt.ifEmpty { nowStr }
                        )
                    }

                    emitSecurityAlert(
                        eventType = "NEW_DEVICE_CONNECTED",
                        details = "Securely linked with ${dev.hostname} (${dev.deviceId}) via End-to-End Encrypted Relay.",
                        severity = "INFO",
                        connStatus = "Connected",
                        deviceName = dev.hostname
                    )
                }
            }
        }

        // Auto-probe local laptop agent on startup
        scope.launch {
            delay(500)
            tryLocalAutoConnect()
        }

        // Real-time telemetry auto-refresh loop (every 2.5 seconds when connected)
        scope.launch {
            while (isActive) {
                delay(2500)
                if (_connectionState.value == ConnectionStatus.CONNECTED && apiService != null) {
                    try {
                        refreshStatus()
                    } catch (e: Exception) {
                        Log.d(tag, "Auto-refresh tick note: ${e.message}")
                    }
                }
            }
        }

        // Heartbeat Watchdog: monitors connectivity in real-time
        scope.launch {
            while (isActive) {
                delay(3000)
                val now = System.currentTimeMillis()
                if (_connectionState.value == ConnectionStatus.CONNECTED && lastHeartbeatTimeMs > 0) {
                    val elapsed = now - lastHeartbeatTimeMs
                    if (elapsed > 30000) {
                        // More than 30s without heartbeat: mark Laptop Offline
                        _connectionState.value = ConnectionStatus.LAPTOP_OFFLINE
                        emitSecurityAlert(
                            eventType = "CONNECTION_STATUS_CHANGED",
                            details = "Laptop appears to be offline or shutdown. No signal received for 30+ seconds.",
                            severity = "WARNING",
                            connStatus = "Laptop Offline"
                        )
                    } else if (elapsed > 12000) {
                        // More than 12s without heartbeat: mark Connection Lost
                        _connectionState.value = ConnectionStatus.CONNECTION_LOST
                        emitSecurityAlert(
                            eventType = "CONNECTION_STATUS_CHANGED",
                            details = "Connection to laptop lost unexpectedly. Awaiting reconnect...",
                            severity = "WARNING",
                            connStatus = "Connection Lost"
                        )
                    }
                }
            }
        }
    }

    private fun getAuthHeader(): String = "Bearer $token"

    fun recordHeartbeat(source: String = "telemetry") {
        lastHeartbeatTimeMs = System.currentTimeMillis()
        val nowStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        _lastSeen.value = nowStr
        if (_connectionState.value != ConnectionStatus.CONNECTED && (cloudRelay.pairedDevice.value != null || apiService != null)) {
            _connectionState.value = ConnectionStatus.CONNECTED
        }
    }

    fun emitSecurityAlert(
        eventType: String,
        details: String,
        severity: String = "INFO",
        connStatus: String? = null,
        deviceName: String? = null
    ) {
        val nowStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        val hostName = deviceName ?: (_agentStatus.value?.hostname ?: cloudRelay.pairedDevice.value?.hostname ?: "Host Laptop")
        val statusStr = connStatus ?: _connectionState.value.label

        // Guard against duplicate consecutive alerts
        val existing = _securityAlerts.value.firstOrNull()
        if (existing != null && existing.eventType == eventType && existing.details == details &&
            System.currentTimeMillis() - lastHeartbeatTimeMs < 5000) {
            return
        }

        val alert = SecurityAlert(
            id = "alert-${System.currentTimeMillis()}-${(1000..9999).random()}",
            eventType = eventType,
            deviceName = hostName,
            deviceType = "Laptop",
            timestamp = nowStr,
            connectionStatus = statusStr,
            details = details,
            severity = severity
        )

        val current = _securityAlerts.value.toMutableList()
        current.add(0, alert)
        _securityAlerts.value = current.take(100)

        // Show native alert notification
        appContext?.let {
            NotificationHelper.showSecurityAlert(it, alert)
        }
    }

    fun onSecurityAlert(alert: SecurityAlert) {
        val current = _securityAlerts.value.toMutableList()
        val idx = current.indexOfFirst { it.id == alert.id }
        if (idx >= 0) {
            current[idx] = alert
        } else {
            current.add(0, alert)
        }
        _securityAlerts.value = current.take(100)
        recordHeartbeat("security_alert")
        appContext?.let {
            NotificationHelper.showSecurityAlert(it, alert)
        }
    }

    /**
     * Generates a secure, short-lived mobile pairing token for the Phone -> Laptop flow.
     */
    fun generateMobileToken(): String {
        val tok = CloudRelayClient.generateToken()
        _mobilePairingToken.value = tok
        _mobileTokenExpiresAt.value = System.currentTimeMillis() + (10 * 60 * 1000) // 10 minutes
        cloudRelay.startListeningWithToken(tok)
        return tok
    }

    /**
     * Maps errors to user-friendly messages without exposing raw stack traces.
     */
    fun mapErrorMessage(e: Throwable?, httpCode: Int? = null, errorBody: String? = null): String {
        val bodyLower = errorBody?.lowercase() ?: ""
        if (bodyLower.contains("expired")) return "Pairing token has expired. Please generate a new token on the laptop."
        if (bodyLower.contains("already used")) return "This pairing token has already been used. Please generate a fresh token."
        if (bodyLower.contains("multiple failed") || bodyLower.contains("3+")) return "Authentication blocked: multiple failed connection attempts detected."
        if (httpCode == 401 || bodyLower.contains("invalid token") || bodyLower.contains("unauthorized")) return "Invalid pairing token. Please check the code and try again."
        if (httpCode == 404 || httpCode == 502 || httpCode == 503 || httpCode == 504) return "Laptop agent is currently offline or unreachable."
        if (e is java.net.SocketTimeoutException) return "Connection timed out. Ensure the laptop agent is running."
        if (e is java.net.ConnectException) return "Could not connect to laptop. Check Wi-Fi / network connection."
        if (e is java.net.UnknownHostException) return "Network host unreachable. Please verify network connection."
        return errorBody?.takeIf { it.isNotBlank() && !it.contains("<html>") } ?: (e?.message ?: "Pairing failure. Please try again.")
    }

    /**
     * Attempts direct connection to local laptop agent over Wi-Fi / USB tunnel.
     */
    suspend fun tryLocalAutoConnect(preferredToken: String? = null): Boolean = withContext(Dispatchers.IO) {
        val tok = (preferredToken ?: token).trim().uppercase()
        val candidateHosts = listOf("defenceiq.onrender.com", "192.168.137.1", "127.0.0.1", "192.168.14.236", "192.168.14.237")
        val candidateTokens = listOf(tok, "DIQ-FUXN-G8CE", "11C6C497")
        for (h in candidateHosts) {
            val targetPort = if (h.contains("onrender.com")) 443 else 8765
            for (t in candidateTokens) {
                try {
                    val res = pairAndConnect(h, targetPort, t)
                    if (res.isSuccess) {
                        Log.i(tag, "Successfully connected to $h:$targetPort with token $t")
                        return@withContext true
                    }
                } catch (e: Exception) {
                    Log.d(tag, "Auto-connect attempt failed for $h:$targetPort: ${e.message}")
                }
            }
        }
        false
    }

    fun connectDirectLan(targetHost: String, targetPort: Int, pairingToken: String, onSuccess: () -> Unit) {
        scope.launch {
            val res = pairAndConnect(targetHost, targetPort, pairingToken)
            if (res.isSuccess) {
                withContext(Dispatchers.Main) {
                    onSuccess()
                }
            }
        }
    }

    /**
     * Token-based pairing without requiring IP address.
     * Binds phone to the unique pairing token and listens on the cloud relay,
     * while also probing local connections.
     */
    fun pairWithToken(pairingToken: String) {
        token = pairingToken.trim().uppercase()
        _connectionState.value = ConnectionStatus.CONNECTING
        cloudRelay.startListeningWithToken(token)
        scope.launch {
            tryLocalAutoConnect(token)
        }
    }

    private fun onCloudThreatAlert(alert: CloudThreatAlert) {
        // Trigger Android push notification
        appContext?.let {
            NotificationHelper.showThreatAlert(it, alert)
        }

        // Convert alert to Incident for UI Feed
        val newInc = Incident(
            incidentId = alert.incidentId,
            createdAt = alert.timestamp,
            updatedAt = alert.timestamp,
            rootPid = 0,
            rootProcessName = alert.affectedProcess,
            involvedPids = emptyList(),
            touchedFiles = alert.affectedFiles,
            networkDestinations = emptyList(),
            signals = alert.signals,
            riskScore = alert.riskScore,
            riskBand = alert.severity,
            contributingSignals = alert.signals.map { ContributingSignal(it, 20, "SYSTEM", it) },
            explanation = "${alert.threatType}. Recommended: ${alert.recommendedAction}",
            actionsTaken = if (alert.severity == "RED") listOf("PROCESS_SUSPENDED") else listOf("ALERT_GENERATED"),
            status = alert.status
        )

        val current = _incidents.value.toMutableList()
        val idx = current.indexOfFirst { it.incidentId == newInc.incidentId }
        if (idx >= 0) {
            current[idx] = newInc
        } else {
            current.add(0, newInc)
        }
        _incidents.value = current
        recordHeartbeat("threat_alert")
    }

    /**
     * Local Wi-Fi pairing test and active REST/WebSocket setup.
     */
    suspend fun pairAndConnect(targetHost: String, targetPort: Int, pairingToken: String): Result<PairResponse> = withContext(Dispatchers.IO) {
        try {
            _connectionState.value = ConnectionStatus.CONNECTING
            host = targetHost.trim()
            port = targetPort
            token = pairingToken.trim().uppercase()

            val isHttps = host.startsWith("https://") || host.contains("onrender.com") || port == 443
            val cleanHost = host.trim()
                .removePrefix("https://")
                .removePrefix("http://")
                .removeSuffix("/")

            val baseUrl = if (isHttps) {
                "https://$cleanHost/"
            } else {
                "http://$cleanHost:$port/"
            }
            val retrofit = Retrofit.Builder()
                .baseUrl(baseUrl)
                .client(okHttpClient!!)
                .addConverterFactory(GsonConverterFactory.create(gson))
                .build()

            apiService = retrofit.create(DefenceIqApiService::class.java)

            // Test pairing endpoint
            val pairRes = apiService!!.pairDevice(
                PairRequest(
                    token = token,
                    deviceName = "Android Mobile",
                    deviceType = "Mobile Phone",
                    confirm = true
                )
            )

            if (!pairRes.isSuccessful || pairRes.body() == null) {
                val errBody = pairRes.errorBody()?.string() ?: ""
                val friendly = mapErrorMessage(null, pairRes.code(), errBody)
                _connectionState.value = ConnectionStatus.DISCONNECTED
                _lastError.value = friendly

                // Emit security alert on auth failure
                emitSecurityAlert(
                    eventType = "AUTHENTICATION_FAILED",
                    details = "Pairing attempt failed: $friendly",
                    severity = "WARNING",
                    connStatus = "Disconnected"
                )

                return@withContext Result.failure(Exception(friendly))
            }

            val pairBody = pairRes.body()!!
            _connectionState.value = ConnectionStatus.CONNECTED
            val nowStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
            _lastConnected.value = nowStr
            _lastSeen.value = nowStr
            recordHeartbeat("pair_success")

            // Initial fetch of status, incidents, and quarantine vault
            refreshStatus()
            refreshIncidents()
            refreshQuarantine()
            refreshSecurityAlerts()

            // Establish real-time WebSocket connection
            connectWebSocket()

            // Also activate cloud relay listener for this token
            cloudRelay.startListeningWithToken(token)

            emitSecurityAlert(
                eventType = "NEW_DEVICE_CONNECTED",
                details = "Successfully paired with laptop ${pairBody.hostname} (${pairBody.lanIp}).",
                severity = "INFO",
                connStatus = "Connected",
                deviceName = pairBody.hostname
            )

            Result.success(pairBody)
        } catch (e: Exception) {
            val friendly = mapErrorMessage(e)
            _connectionState.value = ConnectionStatus.DISCONNECTED
            _lastError.value = friendly
            Log.e(tag, "Pairing exception: $friendly", e)
            Result.failure(Exception(friendly))
        }
    }

    /**
     * Connects to the laptop's live WebSocket alert stream.
     */
    fun connectWebSocket() {
        webSocket?.cancel()
        val isHttps = host.startsWith("https://") || host.contains("onrender.com") || port == 443
        val cleanHost = host.trim()
            .removePrefix("https://")
            .removePrefix("http://")
            .removeSuffix("/")

        val wsScheme = if (isHttps) "wss" else "ws"
        val wsPortPart = if (isHttps) "" else ":$port"
        val wsUrl = "$wsScheme://$cleanHost$wsPortPart/ws/alerts?token=$token"
        val request = Request.Builder().url(wsUrl).build()

        val listener = AlertsWebSocketListener(
            gson = gson,
            onConnected = {
                _connectionState.value = ConnectionStatus.CONNECTED
                recordHeartbeat("ws_open")
            },
            onDisconnected = { reason ->
                Log.w(tag, "WebSocket disconnected: $reason")
                if (_connectionState.value == ConnectionStatus.CONNECTED) {
                    _connectionState.value = ConnectionStatus.CONNECTION_LOST
                    emitSecurityAlert(
                        eventType = "DEVICE_DISCONNECTED_UNEXPECTEDLY",
                        details = "Laptop connection closed unexpectedly ($reason).",
                        severity = "WARNING",
                        connStatus = "Connection Lost"
                    )
                }
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
        recordHeartbeat("ws_frame")
        scope.launch {
            when (frame.type) {
                "security_alert" -> {
                    frame.securityAlert?.let { alert ->
                        onSecurityAlert(alert)
                    }
                }
                "connection_status" -> {
                    frame.connectionStatus?.let { statusStr ->
                        when (statusStr) {
                            "Connected" -> _connectionState.value = ConnectionStatus.CONNECTED
                            "Connection Lost" -> _connectionState.value = ConnectionStatus.CONNECTION_LOST
                            "Laptop Offline" -> _connectionState.value = ConnectionStatus.LAPTOP_OFFLINE
                            "Connecting" -> _connectionState.value = ConnectionStatus.CONNECTING
                            "Disconnected" -> _connectionState.value = ConnectionStatus.DISCONNECTED
                        }
                    }
                    frame.lastSeen?.let { _lastSeen.value = it }
                }
                "incident" -> {
                    frame.incident?.let { newInc ->
                        val current = _incidents.value.toMutableList()
                        val idx = current.indexOfFirst { it.incidentId == newInc.incidentId }
                        if (idx >= 0) {
                            current[idx] = newInc
                        } else {
                            current.add(0, newInc)
                        }
                        _incidents.value = current
                    }
                    refreshStatus()
                }
                "incident_rollback" -> {
                    frame.incidentId?.let { id ->
                        val current = _incidents.value.toMutableList()
                        val idx = current.indexOfFirst { it.incidentId == id }
                        if (idx >= 0) {
                            current[idx] = current[idx].copy(status = "ROLLED_BACK")
                            _incidents.value = current
                        }
                    }
                    refreshStatus()
                }
                "protection_level_changed" -> {
                    frame.level?.let { newLevel ->
                        _agentStatus.value = _agentStatus.value?.copy(protectionLevel = newLevel)
                    }
                }
                "quarantine_restored" -> {
                    refreshQuarantine()
                }
            }
        }
    }

    suspend fun refreshStatus(): Result<AgentStatusResponse> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.getStatus(getAuthHeader())
            if (res.isSuccessful && res.body() != null) {
                _agentStatus.value = res.body()!!
                recordHeartbeat("rest_status")
                res.body()?.lastSeen?.let { _lastSeen.value = it }
                res.body()?.lastConnected?.let { _lastConnected.value = it }
                Result.success(res.body()!!)
            } else {
                Result.failure(Exception("Status query failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun refreshSecurityAlerts(): Result<List<SecurityAlert>> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.getSecurityAlerts(getAuthHeader())
            if (res.isSuccessful && res.body() != null) {
                val alerts = res.body()!!.alerts
                val current = _securityAlerts.value.toMutableList()
                alerts.forEach { remote ->
                    if (current.none { it.id == remote.id }) {
                        current.add(remote)
                    }
                }
                _securityAlerts.value = current.sortedByDescending { it.timestamp }.take(100)
                Result.success(_securityAlerts.value)
            } else {
                Result.failure(Exception("Alerts query failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun refreshIncidents(): Result<List<Incident>> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.getIncidents(getAuthHeader(), limit = 50)
            if (res.isSuccessful && res.body() != null) {
                _incidents.value = res.body()!!.incidents
                recordHeartbeat("rest_incidents")
                Result.success(res.body()!!.incidents)
            } else {
                Result.failure(Exception("Incidents query failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun refreshQuarantine(): Result<List<QuarantinedFile>> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.getQuarantine(getAuthHeader())
            if (res.isSuccessful && res.body() != null) {
                _quarantinedFiles.value = res.body()!!.quarantinedFiles
                recordHeartbeat("rest_quarantine")
                Result.success(res.body()!!.quarantinedFiles)
            } else {
                Result.failure(Exception("Quarantine query failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun rollbackIncident(incidentId: String): Result<RollbackResponse> = withContext(Dispatchers.IO) {
        // Send command through cloud relay
        cloudRelay.requestRollback(incidentId)

        // Also attempt direct REST if local API is reachable
        val service = apiService
        if (service != null) {
            try {
                val res = service.rollbackIncident(incidentId, getAuthHeader())
                if (res.isSuccessful && res.body() != null) {
                    val current = _incidents.value.toMutableList()
                    val idx = current.indexOfFirst { it.incidentId == incidentId }
                    if (idx >= 0) {
                        current[idx] = current[idx].copy(status = "ROLLED_BACK")
                        _incidents.value = current
                    }
                    return@withContext Result.success(res.body()!!)
                }
            } catch (e: Exception) {
                Log.d(tag, "Direct REST rollback failed, relies on cloud relay: ${e.message}")
            }
        }

        // Return optimistic success via cloud relay
        val current = _incidents.value.toMutableList()
        val idx = current.indexOfFirst { it.incidentId == incidentId }
        if (idx >= 0) {
            current[idx] = current[idx].copy(status = "ROLLED_BACK")
            _incidents.value = current
        }
        Result.success(RollbackResponse(true, incidentId, "ROLLED_BACK", emptyMap()))
    }

    suspend fun updateProtectionLevel(level: String): Result<Boolean> = withContext(Dispatchers.IO) {
        cloudRelay.setProtectionLevel(level)
        val service = apiService
        if (service != null) {
            try {
                val res = service.updateProtectionLevel(getAuthHeader(), ProtectionLevelRequest(level))
                if (res.isSuccessful) {
                    _agentStatus.value = _agentStatus.value?.copy(protectionLevel = level)
                    return@withContext Result.success(true)
                }
            } catch (e: Exception) {
                Log.d(tag, "Direct REST level update failed: ${e.message}")
            }
        }
        _agentStatus.value = _agentStatus.value?.copy(protectionLevel = level)
        Result.success(true)
    }

    suspend fun restoreQuarantinedFile(quarantineId: String): Result<Boolean> = withContext(Dispatchers.IO) {
        val service = apiService ?: return@withContext Result.failure(Exception("Not connected"))
        try {
            val res = service.restoreQuarantinedFile(quarantineId, getAuthHeader())
            if (res.isSuccessful) {
                refreshQuarantine()
                Result.success(true)
            } else {
                Result.failure(Exception("File restore failed: HTTP ${res.code()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

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

    fun revokePairing() {
        val service = apiService
        if (service != null) {
            scope.launch(Dispatchers.IO) {
                try {
                    service.revokePairing(getAuthHeader())
                } catch (e: Exception) {
                    Log.d(tag, "Revoke endpoint call: ${e.message}")
                }
            }
        }
        emitSecurityAlert(
            eventType = "DEVICE_REVOKED",
            details = "Device pairing was explicitly revoked and security credentials cleared.",
            severity = "WARNING",
            connStatus = "Disconnected"
        )
        unpair()
    }

    fun unpair() {
        cloudRelay.unpair()
        disconnect()
        _mobilePairingToken.value = null
        _mobileTokenExpiresAt.value = 0L
    }

    fun disconnect() {
        webSocket?.close(1000, "User disconnected")
        webSocket = null
        _connectionState.value = ConnectionStatus.DISCONNECTED
    }
}
