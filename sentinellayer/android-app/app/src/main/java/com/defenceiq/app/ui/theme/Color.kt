package com.defenceiq.app.ui.theme

import androidx.compose.ui.graphics.Color

// Clean Executive White/Light Theme
val LightBackground = Color(0xFFF8FAFC)       // Crisp modern off-white
val LightSurface = Color(0xFFFFFFFF)          // Pure white card surfaces
val LightSurfaceVariant = Color(0xFFF1F5F9)   // Subtle light gray accents
val LightBorderColor = Color(0xFFCBD5E1)      // Crisp slate-300 borders

// Pitch Slate colors guaranteed never to blend or bleach
val TextPrimary = Color(0xFF0F172A)           // Ultra-sharp pitch Slate 900
val TextSecondary = Color(0xFF334155)         // Sharp Slate 700 secondary text
val TextMuted = Color(0xFF64748B)             // High-contrast Slate 500 helper/caption text

// Professional Primary & Accent Colors
val PrimaryBlue = Color(0xFF2563EB)           // Enterprise Royal Blue
val AccentBlue = Color(0xFF0284C7)            // Sky Accent
val CyberBlue = Color(0xFF0284C7)             // Compatible alias
val NeonGreen = Color(0xFF16A34A)             // Professional Forest Green

// Status Badges & Threat Bands
val BandGreen = Color(0xFF16A34A)             // Secure / Online
val BandYellow = Color(0xFFCA8A04)            // Warning
val BandOrange = Color(0xFFEA580C)            // Elevated Risk
val BandRed = Color(0xFFDC2626)               // Critical / Offline
val StatusContained = Color(0xFF6366F1)       // Indigo Contained
val StatusRolledBack = Color(0xFF0284C7)      // Cyan Rolled Back

// Backwards-compatible aliases mapped to the light palette
val DarkBackground = LightBackground
val DarkSurface = LightSurface
val DarkSurfaceVariant = LightSurfaceVariant
val BorderColor = LightBorderColor
