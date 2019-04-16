package dev.w1zzrd.bungee

import java.net.*
import java.nio.ByteBuffer
import java.security.PublicKey
import java.security.Signature
import java.util.concurrent.ThreadLocalRandom

// Reverse TCP connection router (put this on a publicly accessible server)
// A public key is provided so that a route can authenticate itself against this router
class BungeeRTCPRouter(
        private val listenAddr: InetAddress,
        private val port: Int,
        private val routePK: PublicKey
){
    // Map a client to a unique (long) id
    private val clients = HashMap<Socket, Long>()
    private val router = ServerSocket()
    private lateinit var routeSocket: Socket
    private var alive = false
    private var canStart = true
    private val headerBuffer = ByteBuffer.allocateDirect(13) // [ID (byte)][(CUID) long][DLEN (int)]

    fun listen(){
        if(!canStart) throw IllegalStateException("Already started/stopped")
        canStart = false
        alive = true
        router.soTimeout = 1
        router.bind(InetSocketAddress(listenAddr, port))

        // ---- WAIT FOR A VERIFIED ROUTE ENDPOINT ---- //
        var readBytes = 0
        var tryRoute: Socket? = null
        val checkBytes = ByteArray(256)
        val rand = ThreadLocalRandom.current()
        val fromClients = ByteArray(BUFFER_SIZE)
        val fromRoute = ByteArray(BUFFER_SIZE)
        var routeBytes = 0


        fun disconnectRouteServer(){
            tryRoute?.forceClose()
            tryRoute = null
            readBytes = 0
        }

        while(true){
            if(tryRoute == null){
                tryRoute = router.tryAccept()
                if(tryRoute != null){
                    rand.nextBytes(checkBytes)
                    try{
                        // Send the bytes to be signed to remove host
                        tryRoute!!.getOutputStream().write(checkBytes)
                    }catch (e: Throwable){
                        disconnectRouteServer()
                        continue
                    }
                }else continue
            }

            if(tryRoute!!.isClosed || !tryRoute!!.isConnected){
                disconnectRouteServer()
                continue
            }
            try {
                val read = tryRoute!!.getInputStream()
                if (read.available() > 0) {
                    if(read.available() + readBytes > fromClients.size){
                        disconnectRouteServer()
                        continue
                    }
                    readBytes += read.read(fromClients, readBytes, fromClients.size - readBytes)
                }
            }catch(e: Throwable){
                // Forceful disconnection
                disconnectRouteServer()
                continue
            }

            // We have a client. Let's check if they can authenticate
            if(readBytes >= 4 && fromClients.intify(0) == 0x13376969){ // Tell router that you would like to authenticate
                if(readBytes >= (4 + 4)){
                    val signedDataLength = fromClients.intify(4)

                    if(readBytes >= (4 + 4 + signedDataLength)){
                        // We have the signed data; let's verify its integrity
                        val sig = Signature.getInstance("NONEwithRSA") // Raw bytes signed with RSA ;)
                        sig.initVerify(routePK)
                        sig.update(checkBytes)
                        if(sig.verify(fromClients, 4 + 4, signedDataLength)){
                            // We have a verified remote route! :D
                            routeSocket = tryRoute!!
                            break
                        }else{
                            // Verification failed :(
                            disconnectRouteServer()
                            continue
                        }
                    }
                }
            }
        }

        // ---- Accept clients here ---- //
        acceptLoop@while(alive){
            // Accept clients here
            val newClient = router.tryAccept()
            if(newClient != null){
                // New client
                val uid = makeClientUID()
                clients[newClient] = uid
                if(!notifyClientInit(uid)){
                    System.err.println("Unexpected endpoint disconnection")
                    alive = false
                    break@acceptLoop
                }
            }

            for((client, uid) in clients){
                if(client.isClosed || !client.isConnected){
                    if(!notifyClientDisconnect(uid)){
                        System.err.println("Unexpected endpoint disconnection")
                        alive = false
                        break@acceptLoop
                    }
                    clients.remove(client, uid)
                }else{
                    try {
                        val stream = client.getInputStream()
                        if (stream.available() > 0) {
                            val read = stream.read(fromClients)

                            if (read > 0 && !sendClientMessageToServer(uid, fromClients, 0, read)) {
                                System.err.println("Unexpected endpoint disconnection")
                                alive = false
                                break@acceptLoop
                            }
                        }
                    }catch(e: Throwable){
                        // Unexpected client disconnection. Just drop
                        clients.remove(client, uid)

                        if(!notifyClientDisconnect(uid)){
                            System.err.println("Unexpected endpoint disconnection")
                            alive = false
                            break@acceptLoop
                        }
                    }
                }
            }


            // ---- Accept packets from server ---- //
            val routeStream = routeSocket.getInputStream()
            if(routeStream.available() > 0){
                val read = routeStream.read(fromRoute, routeBytes, fromRoute.size - routeBytes)
                var parsed = 0
                parseLoop@while((routeBytes + read) - parsed > 9){
                    when(fromRoute[parsed]){
                        0.toByte() -> {
                            // Parse data packet
                            if((routeBytes + read) - parsed < 13) break@parseLoop // Not enough data

                            val uid = fromRoute.longify(parsed + 1)
                            val dLen = fromRoute.intify(parsed + 1 + 8)

                            if((routeBytes + read) - parsed < 13 + dLen) break@parseLoop // All the data hasn't arrived

                            clients.keys.firstOrNull { clients[it] == uid }
                                    ?.getOutputStream()
                                    ?.write(fromRoute, parsed + 13, dLen)

                            parsed += 13 + dLen
                        }

                        1.toByte() -> {
                            // Handle disconnection
                            val uid = fromRoute.longify(parsed + 1)
                            if(clients.values.contains(uid)){
                                val toDrop = clients.keys.firstOrNull { clients[it] == uid }
                                if(toDrop != null) {
                                    clients.remove(toDrop)
                                    toDrop.forceClose()
                                }
                            }
                            parsed += 9
                        }
                    }
                }

                System.arraycopy(fromRoute, parsed, fromRoute, 0, (routeBytes + read) - parsed)
                routeBytes = (routeBytes + read) - parsed // Amount of unread bytes after parsing
            }
        }
    }

    private fun ServerSocket.tryAccept() = try{ accept() }catch(e: SocketTimeoutException){ null }
    private fun ByteArray.intify(offset: Int)
            = this[offset].toInt().and(0xFF).or(
            this[offset + 1].toInt().and(0xFF).shl(8)
    ).or(
            this[offset + 2].toInt().and(0xFF).shl(16)
    ).or(
            this[offset + 3].toInt().and(0xFF).shl(24)
    )

    private fun ByteArray.longify(offset: Int)
            = this[offset].toLong().and(0xFF).or(
            this[offset + 1].toLong().and(0xFF).shl(8)
    ).or(
            this[offset + 2].toLong().and(0xFF).shl(16)
    ).or(
            this[offset + 3].toLong().and(0xFF).shl(24)
    ).or(
            this[offset + 4].toLong().and(0xFF).shl(32)
    ).or(
            this[offset + 5].toLong().and(0xFF).shl(40)
    ).or(
            this[offset + 6].toLong().and(0xFF).shl(48)
    ).or(
            this[offset + 7].toLong().and(0xFF).shl(56)
    )

    private fun makeClientUID(): Long {
        var uid: Long
        val rand = ThreadLocalRandom.current()

        // Generate a UID
        do uid = rand.nextLong() while(clients.values.contains(uid))

        return uid
    }

    private fun sendClientMessageToServer(uid: Long, data: ByteArray, off: Int = 0, len: Int = data.size)
        = notifyClientAction(uid, 1, len) && sendMessageToServer(data, off, len)

    private fun notifyClientInit(uid: Long) = notifyClientAction(uid, 0)
    private fun notifyClientDisconnect(uid: Long) = notifyClientAction(uid, 2)

    private fun notifyClientAction(uid: Long, action: Byte, meta: Int? = null): Boolean {
        headerBuffer.put(0, action)
        headerBuffer.putLong(1, uid)
        if(meta != null) headerBuffer.putInt(9, meta)
        return sendMessageToServer(headerBuffer.array(), 0, if(meta == null) 9 else 13)
    }

    // If this returns false, message could not be delivered and router should terminate
    private fun sendMessageToServer(rawData: ByteArray, off: Int = 0, len: Int = rawData.size) =
        try{
            routeSocket.getOutputStream().write(rawData, off, len)
            true
        }catch(e: Throwable){
            false
        }
}