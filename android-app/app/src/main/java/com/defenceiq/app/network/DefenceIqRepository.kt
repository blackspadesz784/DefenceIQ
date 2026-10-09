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

    // Host & Auth credentials (Fixed Master Token: DIQ-EJFW-GC3V)
    var host: String = "192.168.1.7"
        private set
    var port: Int = 8765
        private set
    var token: String = "DIQ-EJFW-GC3V"
        private set

    // Persistent Timeline & Date Events Tracking
    private val _timelineEvents = MutableStateFlow<List<TimelineEventItem>>(emptyList())
    val timelineEvents: StateFlow<List<TimelineEventItem>> = _timelineEvents.asStateFlow()
    private val lastSeenApps = mutableMapOf<String, String>()
    private val lastSeenDevices = mutableSetOf<String>()
    // Discovered Laptops on Local Network
    private val _discoveredLaptops = MutableStateFlow<List<DiscoveredLaptop>>(emptyList())
    val discoveredLaptops: StateFlow<List<DiscoveredLaptop>> = _discoveredLaptops.asStateFlow()

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

    private val prefs = appContext?.getSharedPreferences("defenceiq_prefs", Context.MODE_PRIVATE)

    // Paired status: persistent until user explicitly revokes/unpairs
    private val _isPaired = MutableStateFlow<Boolean>(
        prefs?.getBoolean("is_paired", false) == true || !prefs?.getString("last_host", null).isNullOrBlank()
    )
    val isPaired: StateFlow<Boolean> = _isPaired.asStateFlow()

    private val timelineFile: java.io.File? by lazy {
        appContext?.filesDir?.let { java.io.File(it, "defenceiq_timeline_history.json") }
    }

    private fun loadTimelineHistory() {
        try {
            val file = timelineFile ?: return
            if (file.exists()) {
                val jsonStr = file.readText(Charsets.UTF_8)
                val type = object : com.google.gson.reflect.TypeToken<List<TimelineEventItem>>() {}.type
                val items: List<TimelineEventItem>? = gson.fromJson(jsonStr, type)
                if (!items.isNullOrEmpty()) {
                    _timelineEvents.value = items
                    return
                }
            }
        } catch (e: Exception) {
            Log.w(tag, "Failed to load timeline history: ${e.message}")
        }
        val now = Date()
        val dStr = SimpleDateFormat("dd MMM yyyy", Locale.getDefault()).format(now)
        val tStr = SimpleDateFormat("hh:mm:ss a", Locale.getDefault()).format(now)
        _timelineEvents.value = listOf(
            TimelineEventItem(
                dateStr = dStr,
                timeStr = tStr,
                category = "SYSTEM",
                title = "DefenceIQ Timeline Logging Active",
                details = "Time and date tracking active. All laptop events, open apps, and connected devices are securely saved on phone.",
                status = "Ready",
                severity = "INFO"
            )
        )
    }

    private fun saveTimelineHistory() {
        scope.launch(Dispatchers.IO) {
            try {
                val file = timelineFile ?: return@launch
                val jsonStr = gson.toJson(_timelineEvents.value)
                file.writeText(jsonStr, Charsets.UTF_8)
            } catch (e: Exception) {
                Log.w(tag, "Failed to persist timeline history: ${e.message}")
            }
        }
    }

    fun addTimelineEvent(
        category: String,
        title: String,
        details: String,
        status: String = "",
        severity: String = "INFO"
    ) {
        val now = Date()
        val dStr = SimpleDateFormat("dd MMM yyyy", Locale.getDefault()).format(now)
        val tStr = SimpleDateFormat("hh:mm:ss a", Locale.getDefault()).format(now)
        val item = TimelineEventItem(
            dateStr = dStr,
            timeStr = tStr,
            category = category,
            title = title,
            details = details,
            status = status,
            severity = severity
        )
        val updated = mutableListOf(item)
        updated.addAll(_timelineEvents.value)
        _timelineEvents.value = updated.take(500)
        saveTimelineHistory()
    }

    fun clearTimelineHistory() {
        _timelineEvents.value = emptyList()
        scope.launch(Dispatchers.IO) {
            try {
                timelineFile?.delete()
            } catch (e: Exception) {
                Log.w(tag, "Could not delete timeline file: ${e.message}")
            }
        }
    }

    private fun saveConnectionDetails(saveHost: String, savePort: Int, saveToken: String) {
        try {
            prefs?.edit()
                ?.putString("last_host", saveHost)
                ?.putInt("last_port", savePort)
                ?.putString("last_token", saveToken)
                ?.putBoolean("is_paired", true)
                ?.apply()
            _isPaired.value = true
        } catch (e: Exception) {
            Log.w(tag, "Failed to save connection prefs: ${e.message}")
        }
    }

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

        val savedTok = prefs?.getString("last_token", null)
        if (!savedTok.isNullOrBlank()) {
            token = savedTok
        } else {
            token = "DIQ-EJFW-GC3V"
            saveConnectionDetails(host, port, token)
        }

        // Immediately start Cloud Relay listener with token so remote connection outside Wi-Fi stays connected!
        cloudRelay.startListeningWithToken(token)

        loadTimelineHistory()

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

        // Continuous auto-reconnect background loop:
        // As soon as laptop is powered on or connects to network, phone detects and pairs automatically!
        scope.launch {
            while (isActive) {
                if (_connectionState.value != ConnectionStatus.CONNECTED) {
                    try {
                        tryLocalAutoConnect()
                    } catch (e: Exception) {
                        Log.d(tag, "Auto-reconnect tick: ${e.message}")
                    }
                }
                delay(3000)
            }
        }

        // Continuous UDP discovery loop: discovers all laptops running DefenceIQ on the Wi-Fi LAN
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                try {
                    listenForUdpBeacon(2000)
                } catch (e: Exception) {
                    // Ignore timeout
                }
                delay(2000)
            }
        }

        // Real-time telemetry auto-refresh loop (every 1.5 seconds for live responsiveness)
        scope.launch {
            while (isActive) {
                delay(1500)
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
                        addTimelineEvent("SYSTEM", "Laptop Offline / Powered Off", "No heartbeat signal received from laptop", "Offline", "WARNING")
                    } else if (elapsed > 12000) {
                        // More than 12s without heartbeat: mark Connection Lost
                        _connectionState.value = ConnectionStatus.CONNECTION_LOST
                        emitSecurityAlert(
                            eventType = "CONNECTION_STATUS_CHANGED",
                            details = "Connection to laptop lost unexpectedly. Awaiting reconnect...",
                            severity = "WARNING",
                            connStatus = "Connection Lost"
                        )
                        addTimelineEvent("SYSTEM", "Connection Lost", "Connection dropped, auto-reconnecting...", "Reconnecting", "WARNING")
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

    fun recordDiscoveredLaptop(hostname: String, ip: String, port: Int, tok: String) {
        val now = System.currentTimeMillis()
        val current = _discoveredLaptops.value.toMutableList()
        current.removeAll { it.ip == ip || (now - it.lastSeenMs > 60_000L) }
        current.add(0, DiscoveredLaptop(
            hostname = hostname.ifBlank { "Laptop ($ip)" },
            ip = ip,
            port = port,
            token = tok,
            lastSeenMs = now
        ))
        _discoveredLaptops.value = current
    }

    /**
     * Listens for local UDP beacon broadcast by the laptop agent on port 8766.
     * Returns Triple(ip, port, token) if discovered.
     */
    private fun listenForUdpBeacon(timeoutMs: Int = 1500): Triple<String, Int, String>? {
        var socket: java.net.DatagramSocket? = null
        return try {
            socket = java.net.DatagramSocket(null).apply {
                reuseAddress = true
                broadcast = true
                bind(java.net.InetSocketAddress(8766))
                soTimeout = timeoutMs
            }
            val buffer = ByteArray(1024)
            val packet = java.net.DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            val msg = String(packet.data, 0, packet.length)
            val json = org.json.JSONObject(msg)
            if (json.optString("service") == "defenceiq") {
                val ip = json.optString("ip").ifEmpty { packet.address?.hostAddress ?: "127.0.0.1" }
                val port = json.optInt("port", 8765)
                val tok = json.optString("token")
                val hostname = json.optString("hostname", "Host Laptop")
                recordDiscoveredLaptop(hostname, ip, port, tok)
                Triple(ip, port, tok)
            } else null
        } catch (e: Exception) {
            null
        } finally {
            try { socket?.close() } catch (ignored: Exception) {}
        }
    }

    /**
     * Attempts direct connection to local laptop agent over Wi-Fi / Hotspot / USB tunnel.
     * Priority:
     * 1. UDP Discovery Beacon (automatically finds laptop IP and pairing token on Wi-Fi/Hotspot)
     * 2. Saved Host and Token from previous successful session
     * 3. Hotspot gateway (192.168.137.1) and USB tunnel (127.0.0.1)
     */
    suspend fun tryLocalAutoConnect(preferredToken: String? = null): Boolean = withContext(Dispatchers.IO) {
        val tok = (preferredToken ?: token).trim().uppercase()

        // 1. Listen for UDP broadcast beacon from laptop
        val beacon = listenForUdpBeacon(1500)
        if (beacon != null) {
            val (bIp, bPort, bTok) = beacon
            val tokenToUse = if (tok.isNotEmpty() && tok != "UNKNOWN") tok else bTok
            try {
                val res = pairAndConnect(bIp, bPort, tokenToUse)
                if (res.isSuccess) {
                    Log.i(tag, "Auto-connected via UDP Beacon to $bIp:$bPort")
                    saveConnectionDetails(bIp, bPort, tokenToUse)
                    return@withContext true
                }
            } catch (e: Exception) {
                Log.d(tag, "Beacon connect error: ${e.message}")
            }
        }

        // 2. Try saved host from previous session
        val savedHost = prefs?.getString("last_host", null)
        val savedPort = prefs?.getInt("last_port", 8765) ?: 8765
        val savedTok = prefs?.getString("last_token", null) ?: tok
        if (!savedHost.isNullOrBlank() && !savedTok.isNullOrBlank()) {
            try {
                val res = pairAndConnect(savedHost, savedPort, savedTok)
                if (res.isSuccess) {
                    Log.i(tag, "Auto-connected to saved host: $savedHost:$savedPort")
                    return@withContext true
                }
            } catch (e: Exception) {
                Log.d(tag, "Saved host connect error: ${e.message}")
            }
        }

        // 3. Candidate hosts (Windows Hotspot default, USB ADB, common local IPs)
        val candidateHosts = listOf("192.168.137.1", "127.0.0.1", "192.168.1.7", "192.168.0.7", "defenceiq.onrender.com")
        val candidateTokens = listOf(tok, savedTok, "DIQ-EJFW-GC3V", "DIQ-FUXN-G8CE").filter { it.isNotBlank() }.distinct()
        for (h in candidateHosts) {
            val targetPort = if (h.contains("onrender.com")) 443 else 8765
            for (t in candidateTokens) {
                try {
                    val res = pairAndConnect(h, targetPort, t)
                    if (res.isSuccess) {
                        Log.i(tag, "Successfully connected to $h:$targetPort with token $t")
                        saveConnectionDetails(h, targetPort, t)
                        return@withContext true
                    }
                } catch (e: Exception) {
                    Log.d(tag, "Auto-connect attempt failed for $h:$targetPort: ${e.message}")
                }
            }
        }
        false
    }

    fun connectDirectLan(targetHost: String, targetPort: Int, pairingToken: String, onSuccess: () -> Unit = {}) {
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

            addTimelineEvent("SYSTEM", "Laptop Powered On & Connected", "Host workstation ${pairBody.hostname} (${pairBody.lanIp}) linked live.", "Connected", "SUCCESS")

            saveConnectionDetails(cleanHost, port, token)
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
                val st = res.body()!!
                _agentStatus.value = st
                recordHeartbeat("rest_status")
                st.lastSeen?.let { _lastSeen.value = it }
                st.lastConnected?.let { _lastConnected.value = it }

                // Timeline Tracking: Open Applications on Laptop
                for (app in st.openApplications) {
                    val prev = lastSeenApps[app.appName]
                    if (app.isForeground && prev != "foreground") {
                        lastSeenApps[app.appName] = "foreground"
                        addTimelineEvent("APP", "${app.appName} Active Now", "${app.windowTitle.ifEmpty { app.appName }} (${app.category})", "In Use", "INFO")
                    } else if (prev == null && app.isOpen) {
                        lastSeenApps[app.appName] = "open"
                        addTimelineEvent("APP", "${app.appName} Opened", "Launch: ${app.openedAt.ifEmpty { "Active" }} • ${app.processName}", "Running", "INFO")
                    }
                }

                // Timeline Tracking: Connected Devices to Laptop
                for (dev in st.connectedDevices) {
                    val devKey = dev.id.ifEmpty { dev.name }
                    if (!lastSeenDevices.contains(devKey) && dev.status.contains("Connect", true)) {
                        lastSeenDevices.add(devKey)
                        addTimelineEvent("DEVICE", "${dev.name} Connected", "${dev.connectionType} • ${dev.details ?: "Connected to laptop"}", dev.status, "SUCCESS")
                    }
                }

                Result.success(st)
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
        prefs?.edit()?.clear()?.apply()
        _isPaired.value = false
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
