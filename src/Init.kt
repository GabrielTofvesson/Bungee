import dev.w1zzrd.bungee.BungeeRTCPRouter
import dev.w1zzrd.bungee.BungeeRTCPServer
import java.net.InetAddress
import java.util.*

fun main(args: Array<String>){
    if(args[0] == "-s"){
        val server = BungeeRTCPServer(
                InetAddress.getByName("admin.w1zzrd.dev"),
                25565,
                InetAddress.getByName("0.0.0.0"),
                25565,
                "private_key.der"
        )
        Thread {
            val read = Scanner(System.`in`)
            while(true)
                if(read.hasNextInt()){
                    val newPort = read.nextInt()

                    if(newPort == (newPort and 0xFFFF)){
                        println("Updating port: $newPort")
                        server.stop(newPort)
                    } else println("Not a valid number :(")
                }
        }.start()
        while(true)
            try {
                server.start()
                //println("Server dropped. Restarting...")
            }catch(e: Exception){
                e.printStackTrace()
            }
    }else if(args[0] == "-r") {
        while(true)
            try {
                println("Starting router")
                val router = BungeeRTCPRouter(
                        InetAddress.getByName("0.0.0.0"),
                        25565,
                        "public_key.der"
                )
                router.listen()
                println("Router dropped. Restarting...")
            }catch(e: Exception){
                e.printStackTrace()
            }
    }else{
        println("Unknown arguments: ${Arrays.toString(args)}")
    }
}

/*
bufferBytes: 1460
parsed: 1470
length: 16777216
 */