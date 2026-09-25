package com.defenceiq.app.data

import com.google.gson.annotations.SerializedName

/**
 * Endpoint protection status response from GET /status
 */
data class AgentStatusResponse(
    @SerializedName("health_state") val healthState: String,
    @SerializedName("protection_level") val protectionLevel: String,
    @SerializedName("hostname") val hostname: String,
    @SerializedName("lan_ip") val lanIp: String,
    @SerializedName("timestamp") val timestamp: String,
    @SerializedName("monitored_pids_count") val monitoredPidsCount: Int,
    @SerializedName("active_sockets_count") val activeSocketsCount: Int,
    @SerializedName("stats") val stats: SystemStats,
    @SerializedName("engines") val engines: Map<String, String>,
    @SerializedName("system_metrics") val systemMetrics: SystemMetrics? = null,
    @SerializedName("active_window") val activeWindow: ActiveWindowGlance? = null,
    @SerializedName("online_status") val onlineStatus: String? = "ONLINE"
)

data class SystemMetrics(
    @SerializedName("cpu_percent") val cpuPercent: Double = 0.0,
    @SerializedName("cpu_cores_physical") val cpuCoresPhysical: Int = 4,
    @SerializedName("cpu_cores_logical") val cpuCoresLogical: Int = 8,
    @SerializedName("cpu_freq_mhz") val cpuFreqMhz: Double = 0.0,
    @SerializedName("cpu_temp") val cpuTemp: String? = null,
    @SerializedName("ram") val ram: RamMetrics = RamMetrics(),
    @SerializedName("disk") val disk: DiskMetrics = DiskMetrics(),
    @SerializedName("battery") val battery: BatteryMetrics = BatteryMetrics(),
    @SerializedName("gpu") val gpu: GpuMetrics = GpuMetrics(),
    @SerializedName("network") val network: NetworkMetrics = NetworkMetrics(),
    @SerializedName("system_info") val systemInfo: SystemInfoMetrics = SystemInfoMetrics(),
    @SerializedName("top_processes") val topProcesses: List<ProcessMetric> = emptyList()
)

data class RamMetrics(
    @SerializedName("percent") val percent: Double = 0.0,
    @SerializedName("used_gb") val usedGb: Double = 0.0,
    @SerializedName("total_gb") val totalGb: Double = 0.0,
    @SerializedName("available_gb") val availableGb: Double = 0.0
)

data class DiskMetrics(
    @SerializedName("percent") val percent: Double = 0.0,
    @SerializedName("used_gb") val usedGb: Double = 0.0,
    @SerializedName("free_gb") val freeGb: Double = 0.0,
    @SerializedName("total_gb") val totalGb: Double = 0.0,
    @SerializedName("read_speed_kbps") val readSpeedKbps: Double = 0.0,
    @SerializedName("write_speed_kbps") val writeSpeedKbps: Double = 0.0
)

data class BatteryMetrics(
    @SerializedName("percent") val percent: Double? = 100.0,
    @SerializedName("plugged") val plugged: Boolean = true,
    @SerializedName("status") val status: String = "Plugged In ⚡",
    @SerializedName("health") val health: String = "Good",
    @SerializedName("time_left") val timeLeft: String = "AC Power"
)

data class GpuMetrics(
    @SerializedName("name") val name: String = "Integrated GPU",
    @SerializedName("vram_mb") val vramMb: Double = 0.0,
    @SerializedName("status") val status: String = "OK",
    @SerializedName("usage_percent") val usagePercent: Double = 0.0
)

data class NetworkMetrics(
    @SerializedName("status") val status: String = "Online",
    @SerializedName("internet_connected") val internetConnected: Boolean = true,
    @SerializedName("download_speed_kbps") val downloadSpeedKbps: Double = 0.0,
    @SerializedName("upload_speed_kbps") val uploadSpeedKbps: Double = 0.0,
    @SerializedName("bytes_sent_mb") val bytesSentMb: Double = 0.0,
    @SerializedName("bytes_recv_mb") val bytesRecvMb: Double = 0.0
)

data class SystemInfoMetrics(
    @SerializedName("os_name") val osName: String = "Windows",
    @SerializedName("build") val build: String = "",
    @SerializedName("processor") val processor: String = "",
    @SerializedName("architecture") val architecture: String = "",
    @SerializedName("device_name") val deviceName: String = "",
    @SerializedName("uptime") val uptime: String = ""
)

data class ProcessMetric(
    @SerializedName("pid") val pid: Int = 0,
    @SerializedName("name") val name: String = "",
    @SerializedName("cpu_percent") val cpuPercent: Double = 0.0,
    @SerializedName("memory_mb") val memoryMb: Double = 0.0,
    @SerializedName("status") val status: String = "Running"
)

data class ActiveWindowGlance(
    @SerializedName("app_name") val appName: String? = null,
    @SerializedName("process_name") val processName: String? = null,
    @SerializedName("window_title") val windowTitle: String? = null,
    @SerializedName("tab_title") val tabTitle: String? = null,
    @SerializedName("url_domain") val urlDomain: String? = null,
    @SerializedName("category") val category: String? = null,
    @SerializedName("duration_seconds") val durationSeconds: Int = 0
)

data class SystemStats(
    @SerializedName("total_events") val totalEvents: Int,
    @SerializedName("total_incidents") val totalIncidents: Int,
    @SerializedName("incidents_by_band") val incidentsByBand: Map<String, Int>,
    @SerializedName("total_actions") val totalActions: Int
)

/**
 * Individual contributing signal with additive risk weight and explanation
 */
data class ContributingSignal(
    @SerializedName("name") val name: String,
    @SerializedName("weight") val weight: Int,
    @SerializedName("category") val category: String,
    @SerializedName("description") val description: String
)

/**
 * Correlated threat incident with full explainability breakdown
 */
data class Incident(
    @SerializedName("incident_id") val incidentId: String,
    @SerializedName("created_at") val createdAt: String,
    @SerializedName("updated_at") val updatedAt: String,
    @SerializedName("root_pid") val rootPid: Int,
    @SerializedName("root_process_name") val rootProcessName: String,
    @SerializedName("involved_pids") val involvedPids: List<Int> = emptyList(),
    @SerializedName("touched_files") val touchedFiles: List<String> = emptyList(),
    @SerializedName("network_destinations") val networkDestinations: List<String> = emptyList(),
    @SerializedName("signals") val signals: List<String> = emptyList(),
    @SerializedName("risk_score") val riskScore: Int,
    @SerializedName("risk_band") val riskBand: String, // GREEN, YELLOW, ORANGE, RED
    @SerializedName("contributing_signals") val contributingSignals: List<ContributingSignal> = emptyList(),
    @SerializedName("explanation") val explanation: String,
    @SerializedName("actions_taken") val actionsTaken: List<String> = emptyList(),
    @SerializedName("status") val status: String // OPEN, CONTAINED, ROLLED_BACK, RESOLVED
)

data class IncidentsListResponse(
    @SerializedName("count") val count: Int,
    @SerializedName("incidents") val incidents: List<Incident>
)

data class RollbackResponse(
    @SerializedName("success") val success: Boolean,
    @SerializedName("incident_id") val incidentId: String,
    @SerializedName("status") val status: String,
    @SerializedName("results") val results: Map<String, Any>
)

data class QuarantinedFile(
    @SerializedName("quarantine_id") val quarantineId: String,
    @SerializedName("original_path") val originalPath: String,
    @SerializedName("original_name") val originalName: String,
    @SerializedName("file_size_bytes") val fileSizeBytes: Long,
    @SerializedName("sha256") val sha256: String,
    @SerializedName("quarantined_at") val quarantinedAt: String,
    @SerializedName("reason") val reason: String,
    @SerializedName("signals") val signals: List<String> = emptyList(),
    @SerializedName("restored") val restored: Boolean = false
)

data class QuarantineListResponse(
    @SerializedName("count") val count: Int,
    @SerializedName("quarantined_files") val quarantinedFiles: List<QuarantinedFile>
)

data class PairRequest(
    @SerializedName("token") val token: String
)

data class PairResponse(
    @SerializedName("success") val success: Boolean,
    @SerializedName("message") val message: String,
    @SerializedName("lan_ip") val lanIp: String,
    @SerializedName("hostname") val hostname: String,
    @SerializedName("protection_level") val protectionLevel: String
)

data class ProtectionLevelRequest(
    @SerializedName("level") val level: String // basic, balanced, maximum
)

data class WebSocketAlertFrame(
    @SerializedName("type") val type: String,
    @SerializedName("message") val message: String? = null,
    @SerializedName("incident") val incident: Incident? = null,
    @SerializedName("incident_id") val incidentId: String? = null,
    @SerializedName("level") val level: String? = null,
    @SerializedName("timestamp") val timestamp: String? = null
)

data class LanTransport(
    @SerializedName("ip") val ip: String,
    @SerializedName("port") val port: Int,
    @SerializedName("connected_clients") val connectedClients: Int = 0
)

data class UsbDevice(
    @SerializedName("serial") val serial: String,
    @SerializedName("state") val state: String,
    @SerializedName("model") val model: String = "Unknown",
    @SerializedName("usb") val usb: String = ""
)

data class UsbTransport(
    @SerializedName("adb_available") val adbAvailable: Boolean = false,
    @SerializedName("adb_path") val adbPath: String? = null,
    @SerializedName("local_port") val localPort: Int = 8765,
    @SerializedName("remote_port") val remotePort: Int = 8765,
    @SerializedName("devices") val devices: List<UsbDevice> = emptyList(),
    @SerializedName("active_forwards") val activeForwards: List<String> = emptyList(),
    @SerializedName("monitoring") val monitoring: Boolean = false
)

data class BluetoothTransport(
    @SerializedName("ble_supported") val bleSupported: Boolean = false,
    @SerializedName("device_name") val deviceName: String = "DefenceIQ-Agent",
    @SerializedName("service_uuid") val serviceUuid: String = "",
    @SerializedName("advertising") val advertising: Boolean = false,
    @SerializedName("connected_clients") val connectedClients: List<String> = emptyList()
)

data class CloudTransport(
    @SerializedName("enabled") val enabled: Boolean = false,
    @SerializedName("server_url") val serverUrl: String = "https://ntfy.sh",
    @SerializedName("topic") val topic: String = "",
    @SerializedName("total_alerts_sent") val totalAlertsSent: Int = 0
)

data class TransportsResponse(
    @SerializedName("lan") val lan: LanTransport,
    @SerializedName("usb") val usb: UsbTransport,
    @SerializedName("bluetooth") val bluetooth: BluetoothTransport,
    @SerializedName("cloud") val cloud: CloudTransport
)

data class PairedDevice(
    @SerializedName("device_id") val deviceId: String = "LAPTOP-LOCAL",
    @SerializedName("hostname") val hostname: String = "My Laptop",
    @SerializedName("os_name") val osName: String = "Windows",
    @SerializedName("agent_version") val agentVersion: String = "2.1.0",
    @SerializedName("authorized_paths") val authorizedPaths: List<String> = emptyList(),
    @SerializedName("protection_level") val protectionLevel: String = "balanced",
    @SerializedName("paired_at") val pairedAt: String = "",
    @SerializedName("token") val token: String = "",
    @SerializedName("is_cloud_relay") val isCloudRelay: Boolean = true
)

data class CloudThreatAlert(
    @SerializedName("incident_id") val incidentId: String,
    @SerializedName("threat_type") val threatType: String,
    @SerializedName("severity") val severity: String,
    @SerializedName("risk_score") val riskScore: Int,
    @SerializedName("affected_process") val affectedProcess: String,
    @SerializedName("affected_files") val affectedFiles: List<String> = emptyList(),
    @SerializedName("signals") val signals: List<String> = emptyList(),
    @SerializedName("timestamp") val timestamp: String,
    @SerializedName("recommended_action") val recommendedAction: String,
    @SerializedName("explanation") val explanation: String = "",
    @SerializedName("status") val status: String = "OPEN",
    @SerializedName("rollback_available") val rollbackAvailable: Boolean = true
)

data class MonitoringScope(
    @SerializedName("authorized_directories") val authorizedDirectories: List<String> = emptyList(),
    @SerializedName("executable_extensions") val executableExtensions: List<String> = emptyList(),
    @SerializedName("privacy_guarantee") val privacyGuarantee: String = "",
    @SerializedName("containment_policy") val containmentPolicy: String = ""
)
