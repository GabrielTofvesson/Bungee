package dev.w1zzrd.bungee

import java.io.File
import java.net.*
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.*
import java.util.concurrent.ThreadLocalRandom

// TODO: Inherit BungeeServer
// Reverse TCP connection router (put this on a publicly accessible server)
// A public key is provided so that a route can authenticate itself against this router
class BungeeRTCPRouter(
        private val listenAddr: InetAddress,
        private val port: Int,
        private val routePK: PublicKey,
        var verbose: Boolean = true
){
    constructor(listenAddr: InetAddress, port: Int, keyName: String, verbose: Boolean = true):
            this(
                    listenAddr,
                    port,
                    KeyFactory.getInstance("RSA")
                            .generatePublic(X509EncodedKeySpec(File(keyName).readBytes())),
                    verbose
            )


    // Map a client to a unique (long) id
    private val clients = HashMap<Socket, Long>()
    private var router = ServerSocket()
    private lateinit var routeSocket: Socket
    private var alive = false
    private var canStart = true
    private val headerBuffer = ByteBuffer.wrap(ByteArray(13)) // [ID (byte)][(CUID) long][DLEN (int)]


    fun listen() = try{
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
        val wrappedClientBuffer = ByteBuffer.wrap(fromClients)
        val fromRoute = ByteArray(BUFFER_SIZE)
        val wrappedRouteBuffer = ByteBuffer.wrap(fromRoute)
        var routeBytes = 0


        fun disconnectRouteServer(){
            tryRoute?.forceClose()
            tryRoute = null
            readBytes = 0
        }

        var timeout = -1L

        fun status(pref: String, msg: String) = if(verbose) println("$pref: $msg") else Unit
        fun info(msg: String) = status("INFO", msg)
        fun fail(msg: String) = status("FAIL", msg)
        fun success(msg: String) = status("SUCCESS", msg)

        while(true){
            if(tryRoute == null){
                tryRoute = router.tryAccept()
                if(tryRoute != null){
                    timeout = System.currentTimeMillis() + 2000L
                    info("Got RTCP candidate: "+(tryRoute!!.remoteSocketAddress))
                    rand.nextBytes(checkBytes)
                    try{
                        info("Sending stage 1: ${Arrays.toString(checkBytes)}")

                        // Send the bytes to be signed to remove host
                        tryRoute!!.getOutputStream().write(checkBytes)
                    }catch (e: Throwable){
                        disconnectRouteServer()
                        continue
                    }
                }else continue
            }

            // Auth timeout
            val timedOut = (timeout > 0 && timeout < System.currentTimeMillis())
            if(tryRoute!!.isClosed || !tryRoute!!.isConnected || timedOut){
                disconnectRouteServer()
                fail(if(timedOut) "Candidate timed out!" else "Candidate disconnected!")
                timeout = -1L
                continue
            }
            try {
                val read = tryRoute!!.getInputStream()
                if (read.available() > 0) {
                    if(read.available() + readBytes > fromClients.size){
                        disconnectRouteServer()
                        fail("Candidate sent too much data!")
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
            if(readBytes >= 4){ // Tell router that you would like to authenticate
                if(wrappedClientBuffer.getInt(0) != 0x13376969){
                    disconnectRouteServer()
                    fail("Candidate sent improper header")
                    continue
                }

                info("Got valid header")

                if(readBytes >= (4 + 4)){
                    val signedDataLength = wrappedClientBuffer.getInt(4)

                    if(readBytes >= (4 + 4 + signedDataLength)){
                        info("Checking signature...")

                        // We have the signed data; let's verify its integrity
                        val sig = Signature.getInstance("NONEwithRSA") // Raw bytes signed with RSA ;)
                        sig.initVerify(routePK)
                        sig.update(checkBytes)
                        if(sig.verify(fromClients, 4 + 4, signedDataLength)){
                            // We have a verified remote route! :D
                            routeSocket = tryRoute!!
                            success("Candidate RTCP server verified!")
                            break
                        }else{
                            // Verification failed :(
                            disconnectRouteServer()
                            fail("Candidate RTCP server failed verification step!")
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
                            val read = stream.read(fromClients, 0, fromClients.size)

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
                parseLoop@while((routeBytes + read) - parsed > 0){
                    when(fromRoute[parsed]){
                        0.toByte() -> {
                            if((routeBytes + read) - parsed < 10) break@parseLoop

                            // Parse data packet
                            if((routeBytes + read) - parsed < 13) break@parseLoop // Not enough data

                            val uid = wrappedRouteBuffer.getLong(parsed +1)
                            val dLen = wrappedRouteBuffer.getInt(parsed + 1 + 8)

                            if((routeBytes + read) - parsed < 13 + dLen) break@parseLoop // All the data hasn't arrived

                            try {
                                clients.keys.firstOrNull { clients[it] == uid }
                                        ?.getOutputStream()
                                        ?.write(fromRoute, parsed + 13, dLen)
                            }catch(e: Throwable){
                                notifyClientDisconnect(uid)
                            }
                            parsed += 13 + dLen
                        }

                        1.toByte() -> {
                            if((routeBytes + read) - parsed < 10) break@parseLoop

                            // Handle disconnection
                            val uid = wrappedRouteBuffer.getLong(parsed + 1)
                            if(clients.values.contains(uid)){
                                val toDrop = clients.keys.firstOrNull { clients[it] == uid }
                                if(toDrop != null) {
                                    clients.remove(toDrop)
                                    toDrop.forceClose()
                                }
                            }
                            parsed += 9
                        }

                        2.toByte() -> {
                            for(client in clients) client.key.forceClose()
                            clients.clear()
                            break@acceptLoop
                        }
                    }
                }

                System.arraycopy(fromRoute, parsed, fromRoute, 0, (routeBytes + read) - parsed)
                routeBytes = (routeBytes + read) - parsed // Amount of unread bytes after parsing
            }
        }
    }catch(e: Exception){
        e.printStackTrace()
    }finally{
        try{ router.close() }catch(e: Exception){}
        router = ServerSocket()
    }

    private fun ServerSocket.tryAccept() = try{ accept() }catch(e: SocketTimeoutException){ null }

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