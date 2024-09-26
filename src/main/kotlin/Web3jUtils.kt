import okhttp3.OkHttpClient
import org.web3j.protocol.Web3j
import org.web3j.protocol.http.HttpService
import org.web3j.protocol.websocket.WebSocketClient
import org.web3j.protocol.websocket.WebSocketService
import java.net.URI
import java.util.concurrent.TimeUnit.SECONDS

object Web3jUtils {
    fun String.toWeb3j(): Web3j {
        val timeout = 60L

        return Web3j.build(
            when {
                startsWith("http://") || startsWith("https://") ->
                    OkHttpClient.Builder()
                        .connectTimeout(timeout, SECONDS)
                        .readTimeout(timeout, SECONDS)
                        .writeTimeout(timeout, SECONDS)
                        .callTimeout(timeout, SECONDS)
                        .build()
                        .let { HttpService(this, it) }

                startsWith("ws://") || startsWith("wss://") ->
                    WebSocketClient(URI(this))
                        .apply { connectionLostTimeout = timeout.toInt() }
                        .let { WebSocketService(it, false).apply { connect() } }

                else -> throw IllegalArgumentException("Unknown protocol: $this")
            }
        )
    }
}