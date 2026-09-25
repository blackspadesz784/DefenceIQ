package com.defenceiq.app.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.defenceiq.app.network.ConnectionStatus
import com.defenceiq.app.network.DefenceIqRepository
import com.defenceiq.app.ui.alerts.AlertsScreen
import com.defenceiq.app.ui.dashboard.DashboardScreen
import com.defenceiq.app.ui.history.QuarantineScreen
import com.defenceiq.app.ui.pairing.PairingScreen
import com.defenceiq.app.ui.theme.*

sealed class Screen(val route: String, val title: String, val icon: ImageVector) {
    object Dashboard : Screen("dashboard", "Dashboard", Icons.Default.Dashboard)
    object Alerts : Screen("alerts", "Alerts", Icons.Default.Notifications)
    object Vault : Screen("vault", "Vault", Icons.Default.Archive)
    object Transports : Screen("transports", "Comms", Icons.Default.Share)
    object Pairing : Screen("pairing", "Pairing", Icons.Default.Router)
}

class MainActivity : ComponentActivity() {

    private val repository by lazy { DefenceIqRepository(applicationContext) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        com.defenceiq.app.ui.notifications.NotificationHelper.initNotificationChannel(applicationContext)

        setContent {
            DefenceIQTheme {
                val connectionState by repository.connectionState.collectAsState()
                var currentScreen by remember {
                    mutableStateOf<Screen>(
                        if (connectionState == ConnectionStatus.CONNECTED) Screen.Dashboard else Screen.Pairing
                    )
                }

                // If paired successfully, move to Dashboard
                LaunchedEffect(connectionState) {
                    if (connectionState == ConnectionStatus.CONNECTED && currentScreen == Screen.Pairing) {
                        currentScreen = Screen.Dashboard
                    }
                }

                Scaffold(
                    bottomBar = {
                        NavigationBar(
                            containerColor = DarkSurface,
                            contentColor = TextPrimary
                        ) {
                            val items = listOf(Screen.Dashboard, Screen.Alerts, Screen.Vault, Screen.Transports, Screen.Pairing)
                            items.forEach { screen ->
                                val isSelected = currentScreen == screen
                                NavigationBarItem(
                                    icon = {
                                        Icon(
                                            imageVector = screen.icon,
                                            contentDescription = screen.title,
                                            tint = if (isSelected) NeonGreen else TextSecondary
                                        )
                                    },
                                    label = {
                                        Text(
                                            text = screen.title,
                                            color = if (isSelected) NeonGreen else TextSecondary
                                        )
                                    },
                                    selected = isSelected,
                                    onClick = { currentScreen = screen },
                                    colors = NavigationBarItemDefaults.colors(
                                        indicatorColor = DarkSurfaceVariant
                                    )
                                )
                            }
                        }
                    }
                ) { innerPadding ->
                    Surface(
                        modifier = Modifier.padding(innerPadding),
                        color = DarkBackground
                    ) {
                        when (currentScreen) {
                            Screen.Pairing -> PairingScreen(
                                repository = repository,
                                onPairedSuccess = { currentScreen = Screen.Dashboard }
                            )
                            Screen.Dashboard -> DashboardScreen(
                                repository = repository,
                                onNavigateToAlerts = { currentScreen = Screen.Alerts }
                            )
                            Screen.Alerts -> AlertsScreen(
                                repository = repository
                            )
                            Screen.Vault -> QuarantineScreen(
                                repository = repository
                            )
                            Screen.Transports -> TransportsScreen(
                                repository = repository
                            )
                        }
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        repository.disconnect()
    }
}
