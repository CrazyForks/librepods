package me.kavishdevar.librepods.utils

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothSocket
import android.os.ParcelUuid
import android.util.Log
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.io.InputStream
import java.io.OutputStream

class ATTManager(private val device: BluetoothDevice) {
    companion object {
        private const val TAG = "ATTManager"

        private const val OPCODE_READ_REQUEST: Byte = 0x0A
        private const val OPCODE_WRITE_REQUEST: Byte = 0x12
    }

    var socket: BluetoothSocket? = null
    private var input: InputStream? = null
    private var output: OutputStream? = null

    @SuppressLint("MissingPermission")
    fun connect() {
        HiddenApiBypass.addHiddenApiExemptions("Landroid/bluetooth/BluetoothSocket;")
        val uuid = ParcelUuid.fromString("00000000-0000-0000-0000-000000000000")

        socket = createBluetoothSocket(device, uuid)
        socket!!.connect()
        input = socket!!.inputStream
        output = socket!!.outputStream
        Log.d(TAG, "Connected to ATT")
    }

    fun disconnect() {
        try {
            socket?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing socket: ${e.message}")
        }
    }

    fun read(handle: Int): ByteArray {
        val lsb = (handle and 0xFF).toByte()
        val msb = ((handle shr 8) and 0xFF).toByte()
        val pdu = byteArrayOf(OPCODE_READ_REQUEST, lsb, msb)
        writeRaw(pdu)
        return readRaw()
    }

    fun write(handle: Int, value: ByteArray) {
        val lsb = (handle and 0xFF).toByte()
        val msb = ((handle shr 8) and 0xFF).toByte()
        val pdu = byteArrayOf(OPCODE_WRITE_REQUEST, lsb, msb) + value
        writeRaw(pdu)
        readRaw() // usually a Write Response (0x13)
    }

    private fun writeRaw(pdu: ByteArray) {
        output?.write(pdu)
        output?.flush()
        Log.d(TAG, "writeRaw: ${pdu.joinToString(" ") { String.format("%02X", it) }}")
    }

    private fun readRaw(): ByteArray {
        val inp = input ?: throw IllegalStateException("Not connected")
        val buffer = ByteArray(512)
        val len = inp.read(buffer)
        if (len <= 0) throw IllegalStateException("No data read from ATT socket")
        val data = buffer.copyOfRange(0, len)
        Log.wtf(TAG, "Read ${data.size} bytes from ATT")
        Log.d(TAG, "readRaw: ${data.joinToString(" ") { String.format("%02X", it) }}")
        return data
    }

    private fun createBluetoothSocket(device: BluetoothDevice, uuid: ParcelUuid): BluetoothSocket {
        val type = 3 // L2CAP
        val constructorSpecs = listOf(
            arrayOf(device, type, true, true, 31, uuid),
            arrayOf(device, type, 1, true, true, 31, uuid),
            arrayOf(type, 1, true, true, device, 31, uuid),
            arrayOf(type, true, true, device, 31, uuid)
        )

        val constructors = BluetoothSocket::class.java.declaredConstructors
        Log.d("ATTManager", "BluetoothSocket has ${constructors.size} constructors:")

        constructors.forEachIndexed { index, constructor ->
            val params = constructor.parameterTypes.joinToString(", ") { it.simpleName }
            Log.d("ATTManager", "Constructor $index: ($params)")
        }

        var lastException: Exception? = null
        var attemptedConstructors = 0

        for ((index, params) in constructorSpecs.withIndex()) {
            try {
                Log.d("ATTManager", "Trying constructor signature #${index + 1}")
                attemptedConstructors++
                return HiddenApiBypass.newInstance(BluetoothSocket::class.java, *params) as BluetoothSocket
            } catch (e: Exception) {
                Log.e("ATTManager", "Constructor signature #${index + 1} failed: ${e.message}")
                lastException = e
            }
        }

        val errorMessage = "Failed to create BluetoothSocket after trying $attemptedConstructors constructor signatures"
        Log.e("ATTManager", errorMessage)
        throw lastException ?: IllegalStateException(errorMessage)
    }
}
