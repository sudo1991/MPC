import ECDSAValues.prime
import java.math.BigInteger
import java.security.SecureRandom

data class Share(val x: BigInteger, val y: BigInteger) {
    val nonce = BigInteger(prime.bitLength(), SecureRandom()) // 각 참가자가 자신의 랜덤한 값을 생성
}