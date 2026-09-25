package com.defenceiq.app.ui.notifications

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.defenceiq.app.R
import com.defenceiq.app.data.CloudThreatAlert
import com.defenceiq.app.ui.MainActivity

object NotificationHelper {

    private const val CHANNEL_ID = "defenceiq_threat_alerts"
    private const val CHANNEL_NAME = "DefenceIQ Critical Threat Alerts"
    private const val CHANNEL_DESC = "Real-time push notifications for ransomware, malware, and endpoint security threats."

    fun initNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val importance = NotificationManager.IMPORTANCE_HIGH
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, importance).apply {
                description = CHANNEL_DESC
                enableVibration(true)
                enableLights(true)
            }
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    fun showThreatAlert(context: Context, alert: CloudThreatAlert) {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0)
        )

        val priorityIcon = if (alert.severity == "RED") "🚨" else "⚠️"
        val title = "$priorityIcon DefenceIQ: ${alert.threatType}"
        val body = "Process: ${alert.affectedProcess}\nSeverity: ${alert.severity} (${alert.riskScore}/100)\nAction: ${alert.recommendedAction}"

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)

        try {
            NotificationManagerCompat.from(context).notify(alert.incidentId.hashCode(), builder.build())
        } catch (e: SecurityException) {
            // Android 13+ requires POST_NOTIFICATIONS permission
        }
    }
}
