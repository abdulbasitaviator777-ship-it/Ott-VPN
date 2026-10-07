package com.ottvpn.api

import retrofit2.Retrofit
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Concrete Retrofit implementation of VpnApiService.
 */
internal class VpnApiServiceImpl(private val retrofit: Retrofit) : VpnApiService {

    private interface Api {

        @POST("api/auth/register")
        suspend fun register(@Body body: RegisterBody): LoginResponse

        @POST("api/auth/login")
        suspend fun login(@Body body: LoginBody): LoginResponse

        @POST("api/auth/refresh")
        suspend fun refresh(@Body body: RefreshBody): LoginResponse

        @POST("api/auth/logout")
        suspend fun logout(@Body body: RefreshBody): Map<String, String>

        @GET("api/servers/")
        suspend fun listServers(
            @Query("country") country: String = "IN",
            @Query("city") city: String? = null
        ): ServerListResponse

        @GET("api/servers/recommended")
        suspend fun recommendServers(@Query("limit") limit: Int = 5): List<ServerInfo>

        @GET("api/servers/{server_id}")
        suspend fun getServer(@Path("server_id") serverId: String): ServerDetail

        @POST("api/vpn/config")
        suspend fun generateConfig(
            @Query("server_id") serverId: String? = null,
            @Query("split_tunnel") splitTunnel: Boolean = false
        ): VpnConfigResponse

        @POST("api/vpn/revoke")
        suspend fun revokeConfig(@Body body: RevokeBody): Map<String, String>

        @GET("api/vpn/status")
        suspend fun getVpnStatus(): VpnStatusResponse

        @GET("api/vpn/configs")
        suspend fun listConfigs(): List<Map<String, Any>>
    }

    private data class RegisterBody(
        val email: String,
        val password: String,
        val device_info: String
    )

    private data class LoginBody(
        val email: String,
        val password: String,
        val device_info: String
    )

    private data class RefreshBody(
        val refresh_token: String?
    )

    private data class RevokeBody(
        val peer_id: String
    )

    private val api: Api = retrofit.create(Api::class.java)

    override suspend fun register(email: String, password: String, deviceInfo: String): LoginResponse {
        return api.register(RegisterBody(email, password, deviceInfo))
    }

    override suspend fun login(email: String, password: String, deviceInfo: String): LoginResponse {
        return api.login(LoginBody(email, password, deviceInfo))
    }

    override suspend fun refresh(refreshToken: String): LoginResponse {
        return api.refresh(RefreshBody(refreshToken))
    }

    override suspend fun logout(refreshToken: String): Map<String, String> {
        return api.logout(RefreshBody(refreshToken))
    }

    override suspend fun listServers(country: String, city: String?): ServerListResponse {
        return api.listServers(country, city)
    }

    override suspend fun recommendServers(limit: Int): List<ServerInfo> {
        return api.recommendServers(limit)
    }

    override suspend fun getServer(serverId: String): ServerDetail {
        return api.getServer(serverId)
    }

    override suspend fun generateConfig(serverId: String?, splitTunnel: Boolean): VpnConfigResponse {
        return api.generateConfig(serverId, splitTunnel)
    }

    override suspend fun revokeConfig(peerId: String): Map<String, String> {
        return api.revokeConfig(RevokeBody(peerId))
    }

    override suspend fun getVpnStatus(): VpnStatusResponse {
        return api.getVpnStatus()
    }

    override suspend fun listConfigs(): List<Map<String, Any>> {
        return api.listConfigs()
    }
}
