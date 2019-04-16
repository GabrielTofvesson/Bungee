import dev.w1zzrd.bungee.BungeeRTCPRouter
import dev.w1zzrd.bungee.BungeeRTCPServer
import java.io.File
import java.net.InetAddress
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

fun main(args: Array<String>){
    val privKey = KeyFactory.getInstance("RSA")
                    .generatePrivate(PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("./private_key.der"))))

    val pubKey = KeyFactory.getInstance("RSA")
            .generatePublic(X509EncodedKeySpec(Files.readAllBytes(Path.of("./public_key.der"))))

    Thread(Runnable {
        BungeeRTCPRouter(InetAddress.getByName("0.0.0.0"), 6969, pubKey).listen()
    }).start()

    Thread.sleep(20)

    BungeeRTCPServer(
            InetAddress.getByName("0.0.0.0"),
            6969,
            InetAddress.getByName("192.168.1.145"),
            25565,
            privKey
    ).start()
}