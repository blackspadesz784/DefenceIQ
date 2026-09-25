package com.defenceiq.app.network

import android.util.Log
import com.defenceiq.app.data.WebSocketAlertFrame
import com.google.gson.Gson
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener

/**
 * Real-time WebSocket connection listener streaming security telemetry and alerts.
 */
class AlertsWebSocketListener(
    private val gson: Gson,
    private val onConnected: () -> Unit,
    private val onDisconnected: (String) -> Unit,
    private val onFrameReceived: (WebSocketAlertFrame) -> Unit,
    private val onError: (Throwable) -> Unit
) : WebSocketListener() {

    private val tag = "AlertsWS"

    override fun onOpen(webSocket: WebSocket, response: Response) {
        Log.i(tag, "WebSocket connection established with DefenceIQ laptop agent")
        onConnected()
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        Log.d(tag, "WebSocket message received: $text")
        try {
            val frame = gson.fromJson(text, WebSocketAlertFrame::class.java)
            if (frame != null) {
                onFrameReceived(frame)
            }
        } catch (e: Exception) {
            Log.e(tag, "Error parsing WebSocket alert frame: ${e.message}", e)
        }
    }

    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
        Log.w(tag, "WebSocket closing (code: $code, reason: $reason)")
        webSocket.close(1000, null)
        onDisconnected("Closed by server: $reason")
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        Log.i(tag, "WebSocket closed ($code / $reason)")
        onDisconnected("Disconnected")
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        Log.e(tag, "WebSocket failure: ${t.message}", t)
        onError(t)
        onDisconnected(t.message ?: "Connection failure")
    }
}
