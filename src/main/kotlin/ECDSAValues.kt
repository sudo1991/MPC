import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.web3j.crypto.Sign
import java.security.Security

object ECDSAValues {
    init {
        Security.addProvider(BouncyCastleProvider()) // BouncyCastle 프로바이더 추가
    }

    val ecParams = Sign.CURVE_PARAMS!!
    val prime = ecParams.n!!
}