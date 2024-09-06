import org.web3j.crypto.Sign
import java.math.BigInteger
import java.security.SecureRandom

class SharmirSecretSharing(val totalShares: Int, val threshold: Int) {
    private val prime = Sign.CURVE_PARAMS.n

    // 비밀 공유
    fun splitKey(secret: BigInteger): List<Share> {
        val coefficients = List(threshold) { BigInteger(prime.bitLength(), SecureRandom()) }.toMutableList()
        coefficients[0] = secret // 상수항에 비밀 저장

        return (1..totalShares).map { i ->
            val x = BigInteger.valueOf(i.toLong())
            val y = coefficients.foldIndexed(BigInteger.ZERO) { index, acc, coefficient ->
                acc + coefficient * x.pow(index) % prime
            } % prime
            Share(x, y)
        }
    }

    // 비밀 복원
    fun reconstructKey(subsetOfShares: List<Share>): BigInteger {
        require(subsetOfShares.size >= threshold)

        val secret = subsetOfShares.fold(BigInteger.ZERO) { acc, (x_i, y_i) ->
            val li = subsetOfShares.fold(BigInteger.ONE) { accL, (x_j, _) ->
                if (x_i != x_j) accL * x_j * (x_j - x_i).modInverse(prime) % prime else accL
            }
            acc + y_i * li % prime
        }
        return secret % prime
    }
}