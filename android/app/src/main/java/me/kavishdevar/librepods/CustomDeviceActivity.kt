/*
 * LibrePods - AirPods liberated from Apple’s ecosystem
 * 
 * Copyright (C) 2025 LibrePods contributors
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package me.kavishdevar.librepods

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.os.Bundle
import android.os.ParcelUuid
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.annotation.RequiresPermission
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import me.kavishdevar.librepods.screens.AccessibilitySettingsScreen
import me.kavishdevar.librepods.screens.EqualizerSettingsScreen
import me.kavishdevar.librepods.ui.theme.LibrePodsTheme
import org.lsposed.hiddenapibypass.HiddenApiBypass
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

class CustomDevice : ComponentActivity() {
    private val TAG = "AirPodsAccessibilitySettings"
    private var socket: BluetoothSocket? = null
    private val deviceAddress = "28:2D:7F:C2:05:5B"
    private val psm = 31
    private val uuid: ParcelUuid = ParcelUuid.fromString("00000000-0000-0000-0000-00000000000")

    // Data states
    private val isConnected = mutableStateOf(false)
    private val leftAmplification = mutableStateOf(1.0f)
    private val leftTone = mutableStateOf(1.0f)
    private val leftAmbientNoiseReduction = mutableStateOf(0.5f)
    private val leftConversationBoost = mutableStateOf(false)
    private val leftEQ = mutableStateOf(FloatArray(8) { 50.0f })

    private val rightAmplification = mutableStateOf(1.0f)
    private val rightTone = mutableStateOf(1.0f)
    private val rightAmbientNoiseReduction = mutableStateOf(0.5f)
    private val rightConversationBoost = mutableStateOf(false)
    private val rightEQ = mutableStateOf(FloatArray(8) { 50.0f })

    private val singleMode = mutableStateOf(false)
    private val amplification = mutableStateOf(1.0f)
    private val balance = mutableStateOf(0.5f)

    private val retryCount = mutableStateOf(0)
    private val showRetryButton = mutableStateOf(false)
    private val maxRetries = 3

    private var debounceJob: Job? = null

    // Phone and Media EQ state
    private val phoneMediaEQ = mutableStateOf(FloatArray(8) { 50.0f })

    @SuppressLint("MissingPermission")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            LibrePodsTheme {
                val navController = rememberNavController()

                NavHost(navController = navController, startDestination = "main") {
                    composable("main") {
                        AccessibilitySettingsScreen(
                            navController = navController,
                            isConnected = isConnected.value,
                            leftAmplification = leftAmplification,
                            leftTone = leftTone,
                            leftAmbientNoiseReduction = leftAmbientNoiseReduction,
                            leftConversationBoost = leftConversationBoost,
                            rightAmplification = rightAmplification,
                            rightTone = rightTone,
                            rightAmbientNoiseReduction = rightAmbientNoiseReduction,
                            rightConversationBoost = rightConversationBoost,
                            singleMode = singleMode,
                            amplification = amplification,
                            balance = balance,
                            showRetryButton = showRetryButton.value,
                            onRetry = { CoroutineScope(Dispatchers.IO).launch { connectL2CAP() } },
                            onSettingsChanged = { sendAccessibilitySettings() }
                        )
                    }
                    composable("eq") {
                        EqualizerSettingsScreen(
                            navController = navController,
                            leftEQ = leftEQ,
                            rightEQ = rightEQ,
                            singleMode = singleMode,
                            onEQChanged = { sendAccessibilitySettings() },
                            phoneMediaEQ = phoneMediaEQ
                        )
                    }
                }
            }
        }

        // Connect automatically
        CoroutineScope(Dispatchers.IO).launch { connectL2CAP() }
    }

    override fun onDestroy() {
        super.onDestroy()
        socket?.close()
    }

    private suspend fun connectL2CAP() {
        retryCount.value = 0
        // Close any existing socket
        socket?.close()
        socket = null
        while (retryCount.value < maxRetries) {
            try {
                Log.d(TAG, "Starting L2CAP connection setup, attempt ${retryCount.value + 1}")
                HiddenApiBypass.addHiddenApiExemptions("Landroid/bluetooth/BluetoothSocket;")
                val manager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
                val device: BluetoothDevice = manager.adapter.getRemoteDevice(deviceAddress)
                socket = createBluetoothSocket(device, psm)

                withTimeout(5000L) {
                    socket?.connect()
                }

                withContext(Dispatchers.Main) {
                    isConnected.value = true
                    showRetryButton.value = false
                    Log.d(TAG, "L2CAP connection established successfully")
                }

                // Read current settings
                readCurrentSettings()

                // Start listening for responses
                listenForData()

                return
            } catch (e: Exception) {
                Log.e(TAG, "Failed to connect, attempt ${retryCount.value + 1}: ${e.message}")
                retryCount.value++
                if (retryCount.value < maxRetries) {
                    delay(2000) // Wait 2 seconds before retry
                }
            }
        }

        // After max retries
        withContext(Dispatchers.Main) {
            isConnected.value = false
            showRetryButton.value = true
            Log.e(TAG, "Failed to connect after $maxRetries attempts")
        }
    }

    private fun createBluetoothSocket(device: BluetoothDevice, psm: Int): BluetoothSocket {
        val type = 3 // L2CAP
        val constructorSpecs = listOf(
            arrayOf(device, type, true, true, 31, uuid),
            arrayOf(device, type, 1, true, true, 31, uuid),
            arrayOf(type, 1, true, true, device, 31, uuid),
            arrayOf(type, true, true, device, 31, uuid)
        )

        val constructors = BluetoothSocket::class.java.declaredConstructors
        Log.d(TAG, "BluetoothSocket has ${constructors.size} constructors")

        var lastException: Exception? = null
        var attemptedConstructors = 0

        for ((index, params) in constructorSpecs.withIndex()) {
            try {
                Log.d(TAG, "Trying constructor signature #${index + 1}")
                attemptedConstructors++
                return HiddenApiBypass.newInstance(BluetoothSocket::class.java, *params) as BluetoothSocket
            } catch (e: Exception) {
                Log.e(TAG, "Constructor signature #${index + 1} failed: ${e.message}")
                lastException = e
            }
        }

        val errorMessage = "Failed to create BluetoothSocket after trying $attemptedConstructors constructor signatures"
        Log.e(TAG, errorMessage)
        throw lastException ?: IllegalStateException(errorMessage)
    }

    private fun readCurrentSettings() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.d(TAG, "Sending read settings command: 0A1800")
                val readCommand = byteArrayOf(0x0A, 0x18, 0x00)
                socket?.outputStream?.write(readCommand)
                socket?.outputStream?.flush()
                Log.d(TAG, "Read settings command sent")
            } catch (e: IOException) {
                Log.e(TAG, "Failed to send read command: ${e.message}")
            }
        }
    }

    private fun listenForData() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val buffer = ByteArray(1024)
                Log.d(TAG, "Started listening for incoming data")
                while (socket?.isConnected == true) {
                    val bytesRead = socket?.inputStream?.read(buffer)
                    if (bytesRead != null && bytesRead > 0) {
                        val data = buffer.copyOfRange(0, bytesRead)
                        Log.d(TAG, "Received data: ${data.joinToString(" ") { "%02X".format(it) }}")
                        parseSettingsResponse(data)
                    } else if (bytesRead == -1) {
                        Log.d(TAG, "Connection closed by remote device")
                        withContext(Dispatchers.Main) {
                            isConnected.value = false
                        }
                        // Attempt to reconnect
                        connectL2CAP()
                        break
                    }
                }
            } catch (e: IOException) {
                Log.e(TAG, "Connection lost: ${e.message}")
                withContext(Dispatchers.Main) {
                    isConnected.value = false
                }
                // Close socket
                socket?.close()
                socket = null
                // Attempt to reconnect
                connectL2CAP()
            }
        }
    }

    private fun parseSettingsResponse(data: ByteArray) {
        if (data.size < 2 || data[0] != 0x0B.toByte()) {
            Log.d(TAG, "Not a settings response")
            return
        }

        val settingsData = data.copyOfRange(1, data.size)
        if (settingsData.size < 100) { // 25 floats * 4 bytes
            Log.e(TAG, "Settings data too short: ${settingsData.size} bytes")
            return
        }

        val buffer = ByteBuffer.wrap(settingsData).order(ByteOrder.LITTLE_ENDIAN)

        // Global enabled
        val enabled = buffer.float
        Log.d(TAG, "Parsed enabled: $enabled")

        // Left bud
        val newLeftEQ = leftEQ.value.copyOf()
        for (i in 0..7) {
            newLeftEQ[i] = buffer.float
            Log.d(TAG, "Parsed left EQ${i+1}: ${newLeftEQ[i]}")
        }
        leftEQ.value = newLeftEQ
        if (singleMode.value) rightEQ.value = newLeftEQ

        leftAmplification.value = buffer.float
        Log.d(TAG, "Parsed left amplification: ${leftAmplification.value}")
        leftTone.value = buffer.float
        Log.d(TAG, "Parsed left tone: ${leftTone.value}")
        if (singleMode.value) rightTone.value = leftTone.value
        val leftConvFloat = buffer.float
        leftConversationBoost.value = leftConvFloat > 0.5f
        Log.d(TAG, "Parsed left conversation boost: $leftConvFloat (${leftConversationBoost.value})")
        if (singleMode.value) rightConversationBoost.value = leftConversationBoost.value
        leftAmbientNoiseReduction.value = buffer.float
        Log.d(TAG, "Parsed left ambient noise reduction: ${leftAmbientNoiseReduction.value}")
        if (singleMode.value) rightAmbientNoiseReduction.value = leftAmbientNoiseReduction.value

        // Right bud
        val newRightEQ = rightEQ.value.copyOf()
        for (i in 0..7) {
            newRightEQ[i] = buffer.float
            Log.d(TAG, "Parsed right EQ${i+1}: ${newRightEQ[i]}")
        }
        rightEQ.value = newRightEQ

        rightAmplification.value = buffer.float
        Log.d(TAG, "Parsed right amplification: ${rightAmplification.value}")
        rightTone.value = buffer.float
        Log.d(TAG, "Parsed right tone: ${rightTone.value}")
        val rightConvFloat = buffer.float
        rightConversationBoost.value = rightConvFloat > 0.5f
        Log.d(TAG, "Parsed right conversation boost: $rightConvFloat (${rightConversationBoost.value})")
        rightAmbientNoiseReduction.value = buffer.float
        Log.d(TAG, "Parsed right ambient noise reduction: ${rightAmbientNoiseReduction.value}")

        Log.d(TAG, "Settings parsed successfully")

        // Update single mode values if in single mode
        if (singleMode.value) {
            val avg = (leftAmplification.value + rightAmplification.value) / 2
            amplification.value = avg.coerceIn(0f, 1f)
            val diff = rightAmplification.value - leftAmplification.value
            balance.value = (0.5f + diff / (2 * avg)).coerceIn(0f, 1f)
        }
    }

    private fun sendAccessibilitySettings() {
        if (!isConnected.value || socket == null) {
            Log.w(TAG, "Not connected, cannot send settings")
            return
        }

        debounceJob?.cancel()
        debounceJob = CoroutineScope(Dispatchers.IO).launch {
            delay(100)
            try {
                val buffer = ByteBuffer.allocate(103).order(ByteOrder.LITTLE_ENDIAN) // 3 header + 100 data bytes

                buffer.put(0x12)
                buffer.put(0x18)
                buffer.put(0x00)
                buffer.putFloat(1.0f) // enabled

                // Left bud
                for (eq in leftEQ.value) {
                    buffer.putFloat(eq)
                }
                buffer.putFloat(leftAmplification.value)
                buffer.putFloat(leftTone.value)
                buffer.putFloat(if (leftConversationBoost.value) 1.0f else 0.0f)
                buffer.putFloat(leftAmbientNoiseReduction.value)

                // Right bud
                for (eq in rightEQ.value) {
                    buffer.putFloat(eq)
                }
                buffer.putFloat(rightAmplification.value)
                buffer.putFloat(rightTone.value)
                buffer.putFloat(if (rightConversationBoost.value) 1.0f else 0.0f)
                buffer.putFloat(rightAmbientNoiseReduction.value)

                val packet = buffer.array()
                Log.d(TAG, "Packet length: ${packet.size}")
                socket?.outputStream?.write(packet)
                socket?.outputStream?.flush()
                Log.d(TAG, "Accessibility settings sent: ${packet.joinToString(" ") { "%02X".format(it) }}")
            } catch (e: IOException) {
                Log.e(TAG, "Failed to send accessibility settings: ${e.message}")
                withContext(Dispatchers.Main) {
                    isConnected.value = false
                }
                // Close socket
                socket?.close()
                socket = null
            }
        }
    }
}