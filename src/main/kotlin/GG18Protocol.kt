import ECDSAValues.ecParams
import ECDSAValues.prime
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import java.math.BigInteger
import java.security.*
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

class GG18Protocol(private val numberOfParticipants: Int) {
    fun signWithLagrange(
        shares: List<Share>,
        message: ByteArray
    ): Pair<BigInteger, BigInteger> {
        require(value = shares.size >= numberOfParticipants)

        val k = generateDistributedNonce()
        val r = ecParams.g.multiply(k).normalize().affineXCoord.toBigInteger()
            .mod(prime) // r = (k * G).x mod n
            .takeUnless { it == BigInteger.ZERO }
            ?: throw IllegalStateException("r is zero, choose different k")

        val s = combineShares(
            // s = k^−1⋅(m + xr) mod q
            partialS = shares.map {
                k.modInverse(prime).multiply(
                    BigInteger(
                        1,
                        getMessageHash(message = message)
                    ).add(r.multiply(it.y))
                ).mod(prime)
            },
            xValues = shares.map { it.x }
        )

        return Pair(r, s)
    }

    // Verify combined signature function
    fun verifyCombinedSignature(
        publicKey: BigInteger,
        message: ByteArray,
        signature: Pair<BigInteger, BigInteger>
    ): Boolean {
        // r과 s를 DER 형식으로 인코딩
        return Signature.getInstance("SHA256withECDSA", "BC")
            .apply {
                initVerify(convertPublicKey(publicKeyInt = publicKey))
                update(message)
            }.verify(
                DERSequence(
                    ASN1EncodableVector()
                        .apply {
                            add(ASN1Integer(signature.first))
                            add(ASN1Integer(signature.second))
                        }
                ).encoded
            )
    }

    // BigInteger 형태의 Public key를 java.security.PublicKey 객체로 변환
    private fun convertPublicKey(publicKeyInt: BigInteger): PublicKey {
        // Get elliptic curve parameters for secp256k1
        val ecParams = ECNamedCurveTable.getParameterSpec("secp256k1")

        // Use KeyFactory to generate the PublicKey
        return KeyFactory.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME).generatePublic(
            // Create ECPublicKeySpec with the Java ECPoint and curve spec
            ECPublicKeySpec(
                // Manually extract X and Y coordinates from the public key
                // Convert Web3j public key (raw BigInteger) into ECPoint with X and Y
                ECPoint(
                    publicKeyInt.shiftRight(256), // Get the upper 256 bits (X coordinate), Public key size in bits (512 bits = 256 bits for X and 256 bits for Y)
                    publicKeyInt.and(BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)) // Get the lower 256 bits (Y coordinate)
                ),
                ECNamedCurveSpec(ecParams.name, ecParams.curve, ecParams.g, ecParams.n, ecParams.h)
            )
        )
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

    // Hash the message using SHA-256 and return the byte array
    private fun getMessageHash(message: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(message)
    }
}