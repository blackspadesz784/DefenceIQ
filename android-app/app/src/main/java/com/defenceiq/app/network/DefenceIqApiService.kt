package com.defenceiq.app.network

import com.defenceiq.app.data.*
import retrofit2.Response
import retrofit2.http.*

/**
 * Retrofit REST interface for DefenceIQ Laptop Security Agent
 */
interface DefenceIqApiService {

    @GET("/health")
    suspend fun checkHealth(): Response<Map<String, String>>

    @POST("/pair")
    suspend fun pairDevice(
        @Body request: PairRequest
    ): Response<PairResponse>

    @GET("/status")
    suspend fun getStatus(
        @Header("Authorization") authHeader: String
    ): Response<AgentStatusResponse>

    @GET("/incidents")
    suspend fun getIncidents(
        @Header("Authorization") authHeader: String,
        @Query("limit") limit: Int = 50,
        @Query("min_band") minBand: String? = null
    ): Response<IncidentsListResponse>

    @GET("/incidents/{id}")
    suspend fun getIncident(
        @Header("Authorization") authHeader: String,
        @Path("id") incidentId: String
    ): Response<Incident>

    @POST("/incidents/{id}/rollback")
    suspend fun rollbackIncident(
        @Header("Authorization") authHeader: String,
        @Path("id") incidentId: String
    ): Response<RollbackResponse>

    @POST("/incidents/{id}/resolve")
    suspend fun resolveIncident(
        @Header("Authorization") authHeader: String,
        @Path("id") incidentId: String
    ): Response<Map<String, Any>>

    @POST("/protection/level")
    suspend fun updateProtectionLevel(
        @Header("Authorization") authHeader: String,
        @Body request: ProtectionLevelRequest
    ): Response<Map<String, Any>>

    @GET("/quarantine")
    suspend fun getQuarantine(
        @Header("Authorization") authHeader: String,
        @Query("include_restored") includeRestored: Boolean = false
    ): Response<QuarantineListResponse>

    @POST("/quarantine/{id}/restore")
    suspend fun restoreQuarantinedFile(
        @Header("Authorization") authHeader: String,
        @Path("id") quarantineId: String
    ): Response<Map<String, Any>>

    @GET("/transports")
    suspend fun getTransports(
        @Header("Authorization") authHeader: String
    ): Response<TransportsResponse>

    @GET("/pairing/status")
    suspend fun getPairingStatus(): Response<PairingStatusResponse>

    @POST("/token/generate")
    suspend fun generateToken(): Response<GenerateTokenResponse>

    @GET("/security/alerts")
    suspend fun getSecurityAlerts(
        @Header("Authorization") authHeader: String
    ): Response<SecurityAlertsResponse>

    @POST("/revoke-pairing")
    suspend fun revokePairing(
        @Header("Authorization") authHeader: String
    ): Response<Map<String, Any>>
}
