import dev.w1zzrd.bungee.BungeeServer
import java.net.InetAddress

fun main(args: Array<String>){
    // Route localhost:80 -> google.com
    val server = BungeeServer(
            InetAddress.getByName("0.0.0.0"), 25565,
            InetAddress.getByName("192.168.1.145"), 25565
    )
    server.start()
    server.waitFor()
}