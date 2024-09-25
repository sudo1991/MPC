import ECDSAValues.ecParams
import ECDSAValues.prime
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.web3j.crypto.Sign
import org.web3j.utils.Numeric
import java.math.BigInteger
import java.security.SecureRandom

class GG18Protocol(private val numberOfParticipants: Int) {
    fun signWithLagrange(
        shares: List<Share>,
        message: ByteArray
    ): Sign.SignatureData { // Triple을 사용하여 r, s, v를 반환
        require(value = shares.size >= numberOfParticipants)

        val k = generateDistributedNonce()
        // r = (k * G).x mod n
        val pointR = ecParams.g.multiply(k).normalize() // 점 R을 얻음
        val r = pointR.affineXCoord.toBigInteger().mod(prime)
            .takeUnless { it == BigInteger.ZERO }
            ?: throw IllegalStateException("r is zero, choose different k")
        // s = k^−1⋅(m + xr) mod q
        val s = combineShares(
            partialS = shares
                .map {
                    k
                        .modInverse(prime)
                        .multiply(BigInteger(1, message).add(r.multiply(it.y)))
                        .mod(prime)
                },
            xValues = shares.map { it.x }
        )
            .let {
                if (it > prime.shiftRight(1)) {  // n/2 보다 크면 절반으로 나눔
                    prime.subtract(it) // s 값을 더 작은 값으로 변환
                } else {
                    it
                }
            }

        // r, s 값의 범위 확인
        require(r.signum() > 0 && r < prime) { "Invalid r value" }
        require(s.signum() > 0 && s < prime) { "Invalid s value" }

        // r, s 값을 32바이트로 패딩 (필요할 경우)
        val rPadded = Numeric.toBytesPadded(r, 32)
        val sPadded = Numeric.toBytesPadded(s, 32)

        // 패딩 확인
        require(rPadded.size == 32) { "r value is not correctly padded" }
        require(sPadded.size == 32) { "s value is not correctly padded" }

        return Sign.SignatureData(
            (if (pointR.affineYCoord.toBigInteger().testBit(0)) {
                28.toBigInteger()
            } else {
                27.toBigInteger()
            }).toByteArray(),                // v
            rPadded, // r (32바이트 패딩된 값)
            sPadded  // s (32바이트 패딩된 값)
        )
    }

    fun verifyCombinedSignature(
        publicKey: BigInteger,
        message: ByteArray,
        combinedSignatureData: Sign.SignatureData
    ): Boolean {
        // BouncyCastle ECDSA 서명 검증
        val signer = ECDSASigner()

        // publicKey를 BouncyCastle의 ECPublicKeyParameters로 변환
        val ecPublicKeyParameters = convertPublicKey(publicKey)

        // 서명 검증을 위해 검증자 초기화
        signer.init(false, ecPublicKeyParameters)

        // r과 s 값
        val r = BigInteger(1, combinedSignatureData.r)
        val s = BigInteger(1, combinedSignatureData.s)

        // 서명 검증
        return signer.verifySignature(message, r, s)
    }

    // BigInteger 형태의 Public key를 ECPublicKeyParameters로 변환
    private fun convertPublicKey(publicKeyInt: BigInteger): ECPublicKeyParameters {
        // Public key에서 X와 Y 좌표 추출
        val xCoord = publicKeyInt.shiftRight(256) // 상위 256비트는 X 좌표
        val yCoord = publicKeyInt.and(BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)) // 하위 256비트는 Y 좌표

        // ECPoint 생성
        val curve = ecParams.curve
        val ecPoint = curve.createPoint(xCoord, yCoord)

        // ECDomainParameters 생성
        val domainParameters = ECDomainParameters(
            curve,
            ecParams.g,
            ecParams.n,
            ecParams.h
        )

        // ECPublicKeyParameters 생성
        return ECPublicKeyParameters(ecPoint, domainParameters)
    }

    // 라그랑주 보간법 = 주어진 n개의 점을 지나는 다항식을 구하는 방법
    private fun calculateLagrangeCoefficients(xValues: List<BigInteger>): List<BigInteger> {
        return xValues.map { xi -> // 각 x_i에 대한 라그랑주 계수 계산
            xValues.fold(BigInteger.ONE) { acc, xj ->
                if (xi != xj) acc * xj * (xj - xi).modInverse(prime) % prime else acc
            }
        }
    }

    // 공동 난수 생성 (분산된 방식)
    private fun generateDistributedNonce(): BigInteger {
        return List(size = numberOfParticipants) { // 서명에 참가하는 참가자 수 만큼의 리스트 생성
            BigInteger(prime.bitLength(), SecureRandom()) // 각 참가자가 자신의 랜덤한 값을 생성
        }
            .reduce { acc, share -> acc.add(share) % prime } // 임시 키(또는 nonce)를 각 참가자의 값들의 합으로 계산
    }

    private fun combineShares(partialS: List<BigInteger>, xValues: List<BigInteger>): BigInteger {
        return partialS
            .zip(other = calculateLagrangeCoefficients(xValues = xValues)) // 라그랑주 보간법을 사용하여 x-좌표에 대응하는 라그랑주 계수 계산
            .fold(BigInteger.ZERO) { acc, (partial, coeff) ->
                acc.add(partial.multiply(coeff)).mod(prime)
            } // (acc += 서명 값 x 라그랑주 계수) mod prime
    }
}