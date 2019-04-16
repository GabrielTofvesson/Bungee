package dev.w1zzrd.bungee

import java.net.*

const val SERVER_CONNECTION_BACKLOG = 65536
const val BUFFER_SIZE = 16777216       // 16 MiB communication buffer

class BungeeServer(
        private val listenAddr: InetAddress,
        private val port: Int,
        private val routeTo: InetAddress,
        private val routePort: Int
){
    private var canStart = true
    private val serverSocket = ServerSocket()
    private val buffer = ByteArray(BUFFER_SIZE)
    private val listenThread = Thread(this::acceptSocket)
    private val clients = HashMap<Socket, Socket>()
    private var alive = false

    init {
        serverSocket.soTimeout = 1
    }

    /**
     * Start listening for incoming connections.
     */
    fun start(){
        if(!canStart) throw IllegalStateException("Already started/stopped")
        canStart = false

        // Set up server socket
        serverSocket.bind(InetSocketAddress(listenAddr, port), SERVER_CONNECTION_BACKLOG)

        listenThread.start()
    }

    fun waitFor() = listenThread.join()

    private fun acceptSocket(){
        alive = true
        while(alive) {
            // Accept new clients
            serverSocket.acceptPassthrough()

            // Remove connections that have been dropped
            purgeDeadConnections()

            // Forward data
            for ((clientSocket, routeSocket) in clients) {
                // Bidirectional communication
                clientSocket.forwardConnection(routeSocket)
                routeSocket.forwardConnection(clientSocket)
            }
        }
    }

    private fun purgeDeadConnections(){
        for((clientSocket, routeSocket) in clients){
            if(
                    !(clientSocket.isConnected && routeSocket.isConnected) ||
                    clientSocket.isClosed ||
                    routeSocket.isClosed
            ){
                purgeConnectionRoute(clientSocket, routeSocket)
            }
        }
    }

    private fun purgeConnectionRoute(clientSocket: Socket, routeSocket: Socket){
        clientSocket.forceClose()
        routeSocket.forceClose()
        clients.remove(clientSocket, routeSocket)
    }

    private fun Socket.forceClose() = try{ close() }catch(t: Throwable){}

    private fun Socket.forwardConnection(dest: Socket){
        val from = getInputStream()
        val to = dest.getOutputStream()

        try {
            if (from.available() > 0) {
                val read = from.read(buffer, 0, buffer.size)
                if (read > 0) to.write(buffer, 0, read)
            }
        }catch(t: Throwable){
            // Probably a disconnection tbh
            purgeConnectionRoute(this, dest)
        }
    }


    private fun ServerSocket.acceptPassthrough(){
        val client: Socket
        try {
            client = accept()
        } catch (e: SocketTimeoutException) {
            // Accepting clients timed out: no new clients
            return
        }

        // Create a corresponding, outgoing connection for the new client
        clients[client] = Socket(routeTo, routePort)
    }
}