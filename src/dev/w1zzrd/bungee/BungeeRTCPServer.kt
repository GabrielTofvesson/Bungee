package dev.w1zzrd.bungee

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.security.PrivateKey
import java.security.Signature

// TODO: Inherit BungeeServer
// Private key used to authenticate against router
class BungeeRTCPServer(
        private val routerAddr: InetAddress,
        private val routerPort: Int,
        private val routeTo: InetAddress,
        private val routePort: Int,
        private val privateKey: PrivateKey
){
    // A map of a client UID to the "virtual client" (a socket from this server to the provided route endpoint)
    private val vClients = HashMap<Long, Socket>()
    private var canStart = true
    private val serverSocket = Socket()
    private val buffer = ByteArray(BUFFER_SIZE)
    private val clientBuffer = ByteArray(BUFFER_SIZE)
    private var alive = false
    private val headerBuffer = ByteBuffer.allocateDirect(13)

    fun start(){
        if(!canStart) throw IllegalStateException("Already started/stopped")
        canStart = false

        serverSocket.connect(InetSocketAddress(routerAddr, routerPort))

        // Await data to sign
        val read = serverSocket.getInputStream()
        val write = serverSocket.getOutputStream()
        var readCount = 0
        while(readCount < 256) readCount += read.read(buffer, readCount, buffer.size - readCount)

        val sig = Signature.getInstance("NONEwithRSA")
        sig.initSign(privateKey)
        sig.update(buffer, 0, 256)
        val signLen = sig.sign(buffer, 8, buffer.size - 8)
        buffer[0] = 0x69.toByte()
        buffer[1] = 0x69.toByte()
        buffer[2] = 0x37.toByte()
        buffer[3] = 0x13.toByte()
        buffer[4] = signLen.and(0xFF).toByte()
        buffer[5] = signLen.ushr(8).and(0xFF).toByte()
        buffer[6] = signLen.ushr(16).and(0xFF).toByte()
        buffer[7] = signLen.ushr(24).and(0xFF).toByte()

        // Send signature
        write.write(buffer, 0, 8 + signLen)

        var bufferBytes = 0
        alive = true
        while(alive){
            if(read.available() > 0)
                bufferBytes += read.read(buffer, bufferBytes, buffer.size - bufferBytes)

            var parsed = 0
            parseLoop@while(bufferBytes - parsed > 9){
                val uid = buffer.longify(parsed + 1)

                when(buffer[parsed]){
                    0.toByte() -> {
                        // New client
                        vClients[uid] = Socket(routeTo, routePort)
                    }

                    1.toByte() -> {
                        // Data from client
                        if(bufferBytes - parsed > 13){
                            val dLen = buffer.intify(parsed + 9)
                            if(bufferBytes < parsed + dLen) break@parseLoop // Not enough data
                            try {
                                // Send data to server
                                vClients[uid]?.getOutputStream()?.write(buffer, parsed + 13, dLen)
                            }catch(e: Throwable){
                                notifyClientDrop(uid)
                            }

                            parsed += 4 + dLen
                        }else break@parseLoop // Not enough data
                    }

                    2.toByte() -> {
                        // Remote disconnection
                        vClients[uid]?.forceClose()
                        vClients.remove(uid)
                    }
                }

                parsed += 9
            }

            System.arraycopy(buffer, parsed, buffer, 0, bufferBytes - parsed)
            bufferBytes -= parsed


            // Accept data from route endpoint
            for((uid, client) in vClients){
                try {
                    val stream = client.getInputStream()
                    if (read.available() > 0) {
                        val clientRead = stream.read(clientBuffer, 0, clientBuffer.size)
                        if (clientRead > 0) sendVClientPacket(uid, clientBuffer, 0, clientRead)
                    }
                }catch(e: Throwable){
                    notifyClientDrop(uid)
                }
            }
        }
    }

    fun sendVClientPacket(uid: Long, data: ByteArray, off: Int, len: Int){
        notifyClientAction(uid, 0, data.size)
        sendMessageToRouter(data, off, len)
    }
    fun notifyClientDrop(uid: Long) = notifyClientAction(uid, 1)
    fun notifyClientAction(uid: Long, action: Byte, meta: Int? = null){
        headerBuffer.put(0, action)
        headerBuffer.putLong(1, uid)
        if(meta != null) headerBuffer.putInt(9, meta)
        sendMessageToRouter(headerBuffer.array(), 0, if(meta == null) 9 else 13)
    }
    fun sendMessageToRouter(data: ByteArray, off: Int, len: Int){
        serverSocket.getOutputStream().write(data, off, len)
    }
}