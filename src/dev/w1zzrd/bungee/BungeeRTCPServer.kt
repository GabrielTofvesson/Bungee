package dev.w1zzrd.bungee

import java.io.File
import java.net.*
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.atomic.AtomicBoolean

// TODO: Inherit BungeeServer
// Private key used to authenticate against router
class BungeeRTCPServer(
        private val routerAddr: InetAddress,
        private val routerPort: Int,
        private val routeTo: InetAddress,
        private var routePort: Int,
        private val privateKey: PrivateKey
){

    constructor(routerAddr: InetAddress, routerPort: Int, routeTo: InetAddress, routePort: Int, keyName: String):
            this(
                    routerAddr,
                    routerPort,
                    routeTo,
                    routePort,
                    KeyFactory.getInstance("RSA")
                            .generatePrivate(PKCS8EncodedKeySpec(File(keyName).readBytes()))
            )



    // A map of a client UID to the "virtual client" (a socket from this server to the provided route endpoint)
    private val vClients = HashMap<Long, Socket>()
    private val canStart = AtomicBoolean(true)
    private var serverSocket = Socket()
    private val buffer = ByteArray(BUFFER_SIZE)
    private val wrappedServerBuffer = ByteBuffer.wrap(buffer)
    private val clientBuffer = ByteArray(BUFFER_SIZE)
    private val alive = AtomicBoolean(false)
    private val headerBuffer = ByteBuffer.wrap(ByteArray(13))

    fun start(){
        synchronized(canStart) {
            if (!canStart.get()) return@start
            canStart.set(false)
        }

        println("Starting RTCP server")

        serverSocket.connect(InetSocketAddress(routerAddr, routerPort))

        // Await data to sign
        val read = serverSocket.getInputStream()
        val write = serverSocket.getOutputStream()
        var readCount = 0
        try {
            while (readCount < 256) readCount += read.read(buffer, readCount, buffer.size - readCount)
        }catch(e: Exception){
            println("Encountered an error when authenticating")
            stop()
            return
        }
        val sig = Signature.getInstance("NONEwithRSA")
        sig.initSign(privateKey)
        sig.update(buffer, 0, 256)
        val signLen = sig.sign(buffer, 8, buffer.size - 8)
        wrappedServerBuffer.putInt(0, 0x13376969)
        wrappedServerBuffer.putInt(4, signLen)

        // Send signature
        write.write(buffer, 0, 8 + signLen)

        var bufferBytes = 0
        synchronized(alive){alive.set(true)}
        while(synchronized(alive){alive.get()}){
            if(read.available() > 0)
                bufferBytes += read.read(buffer, bufferBytes, buffer.size - bufferBytes)

            var parsed = 0
            parseLoop@while((bufferBytes - parsed) > 9){
                val action = wrappedServerBuffer.get(parsed)
                val uid = wrappedServerBuffer.getLong(parsed + 1)

                when(action){
                    // New client
                    0.toByte() -> vClients[uid] = Socket(routeTo, routePort, InetAddress.getByName("localhost"), 0)

                    1.toByte() -> {
                        // Data from client
                        if((bufferBytes - parsed) > 13){
                            // Get packet size
                            val dLen = wrappedServerBuffer.getInt(parsed + 9)

                            // Check if entire packet has been received yet
                            if((bufferBytes - parsed - 13) < dLen) break@parseLoop // Not enough data

                            try {
                                // Send data to server
                                vClients[uid]?.getOutputStream()?.write(buffer, parsed + 13, dLen)
                            }catch(e: Throwable){
                                notifyClientDrop(uid)
                            }

                            parsed += 4 + dLen
                        }else break@parseLoop // Not enough data
                    }

                    // Remote disconnection
                    2.toByte() -> vClients.remove(uid)?.forceClose()
                }

                parsed += 9
            }

            try{
                if(parsed > bufferBytes) println("Packet read overflow (by ${parsed - bufferBytes} bytes) detected!")
                System.arraycopy(buffer, Math.min(bufferBytes, parsed), buffer, 0, Math.max(0, bufferBytes - parsed))
                bufferBytes = Math.max(0, bufferBytes - parsed)
            }catch(e: Exception){
                println("bufferBytes: $bufferBytes\nparsed: $parsed\nlength: ${buffer.size}\n")
                throw e
            }


            // Accept data from route endpoint
            for((uid, client) in vClients){
                try {
                    val stream = client.getInputStream()
                    if (stream.available() > 0) {
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
        notifyClientAction(uid, 0, len)
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

    fun stop(newPort: Int = routePort) = synchronized(canStart){
        synchronized(alive) {
            if (alive.get()) {
                try {
                    sendMessageToRouter(byteArrayOf(2), 0, 1)
                } catch (e: Exception) {
                } finally {
                    try {
                        serverSocket.forceClose()
                    } catch (e: Exception) {
                    }
                }
            }
            alive.set(false)
            canStart.set(true)
            routePort = newPort
            serverSocket = Socket()
            println("RTCP server Stopped")
        }
    }
}