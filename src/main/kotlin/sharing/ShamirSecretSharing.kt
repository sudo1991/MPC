package sharing

import ECDSAValues.prime
import java.math.BigInteger
import java.security.SecureRandom

class ShamirSecretSharing(val totalShares: Int, val threshold: Int) {
    // 비밀 공유
    fun splitKey(secret: BigInteger): List<Share> {
        // 임의의 k-1 차수 다항식 계수 생성 (계수는 소수(prime) 내에서 무작위로 생성)
        val coefficients = MutableList(threshold) {
            BigInteger(prime.bitLength(), SecureRandom()).mod(prime)
        }
        coefficients[0] = secret // 상수항에 비밀 저장

        // 각 x값에서 다항식을 평가하여 (x, y) 형태의 share 생성
        return (1..totalShares).map { i ->
            val x = BigInteger.valueOf(i.toLong())
            val y = coefficients.foldIndexed(BigInteger.ZERO) { index, acc, coefficient ->
                acc + coefficient * x.pow(index) % prime
            } % prime
            Share(x, y)
        }
    }

    // 비밀 복원 (k개의 share를 사용하여 비밀 복원)
    fun reconstructKey(subsetOfShares: List<Share>): BigInteger {
        require(subsetOfShares.size >= threshold) { "Threshold 이상 수의 공유가 필요합니다." }

        val secret = subsetOfShares.fold(BigInteger.ZERO) { acc, (x_i, y_i) ->
            val li = subsetOfShares.fold(BigInteger.ONE) { accL, (x_j, _) ->
                if (x_i != x_j) accL * x_j * (x_j - x_i).modInverse(prime) % prime else accL
            }
            acc + y_i * li % prime
        }
        val positiveSecret = secret.mod(prime)

        return if (positiveSecret < BigInteger.ZERO) positiveSecret.add(prime) else positiveSecret
    }
}