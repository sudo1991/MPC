package gg18

import ECDSAValues.ecParams
import ECDSAValues.prime
import Web3jUtils.toWeb3j
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.web3j.crypto.ECDSASignature
import org.web3j.crypto.RawTransaction
import org.web3j.crypto.Sign
import org.web3j.crypto.TransactionEncoder.createEip155SignatureData
import org.web3j.crypto.TransactionEncoder.encode
import org.web3j.protocol.core.methods.response.TransactionReceipt
import org.web3j.utils.Numeric
import org.web3j.utils.Numeric.toHexString
import java.math.BigInteger

class GG18Protocol(val message: ByteArray, val numberOfParticipants: Int) {
    private val web3j = "https://quorum.ledgermaster.kr/".toWeb3j()

    private val signatureFragments = mutableListOf<SignatureFragment>()

    fun addSignatureFragment(signatureFragment: SignatureFragment) {
        signatureFragments.add(element = signatureFragment)
    }

    private val temporaryKeys = mutableListOf<BigInteger>()

    fun addTemporaryKey(key: BigInteger) {
        // TODO("임시 키 검증 로직")
        temporaryKeys.add(key)
    }

    private val k by lazy {
        check(temporaryKeys.size == numberOfParticipants) { "Number of temporary keys submitted is different than number of participants." }

        temporaryKeys.reduce { acc, share ->
            acc.add(share).mod(prime)
        } // 임시 키(또는 nonce)를 각 참가자의 값들의 합으로 계산
    }
    val r by lazy {
        // r = (G * k).x mod n
        ecParams.g.multiply(k).normalize().affineXCoord.toBigInteger().mod(prime)
            .takeIf { it.signum() > 0 && it < prime }
            ?: throw IllegalStateException("Invalid r value")
    }

    fun calculateS(s: BigInteger): BigInteger {
        return k.modInverse(prime).multiply(BigInteger(1, message).add(s))
            .mod(prime) // s = r.multiply(share.y)
    }

    fun signWithLagrange(publicKey: BigInteger): Sign.SignatureData { // Triple을 사용하여 r, s, v를 반환
        check(signatureFragments.size == numberOfParticipants) { "Number of signature fragments submitted is different than number of participants." }

        // s = k^−1⋅(m + xr) mod q
        val s = combineShares(
            partialS = signatureFragments.map { it.s },
            xValues = signatureFragments.map { it.x }
        )
            .let { if (it > prime.shiftRight(1)) prime.subtract(it) else it } // n/2 보다 크면 절반으로 나눔
            .takeIf { it.signum() > 0 && it < prime }
            ?: throw IllegalStateException("Invalid s value")

        var v = 0
        for (i in 0..1) {
            if (Sign.recoverFromSignature(i, ECDSASignature(r, s), message) == publicKey) {
                v = i + 27
                break
            }
        }
        check(v == 27 || v == 28) { "Invalid v" }

        return Sign.SignatureData(
            v.toByte(),                   // v
            Numeric.toBytesPadded(r, 32), // r (32바이트 패딩된 값)
            Numeric.toBytesPadded(s, 32)  // s (32바이트 패딩된 값)
        )
            .also {
                println(
                    message = "Padded r = ${BigInteger(it.r)}, " +
                        "Padded s = ${BigInteger(it.s)}, " +
                        "v = ${BigInteger(it.v)}"
                )
            }
    }

    fun verifyCombinedSignature(
        publicKey: BigInteger,
        combinedSignatureData: Sign.SignatureData
    ): Boolean {
        // BouncyCastle ECDSA 서명 검증
        return ECDSASigner()
            .apply { init(false, convertPublicKey(publicKey = publicKey)) } // 서명 검증을 위해 검증자 초기화
            .verifySignature(
                message,
                BigInteger(1, combinedSignatureData.r),
                BigInteger(1, combinedSignatureData.s)
            )
    }

    fun sendTransaction(
        rawTransaction: RawTransaction,
        combinedSignatureData: Sign.SignatureData,
        chainId: Long
    ): String {
        return web3j.ethSendRawTransaction(
            toHexString(
                encode(
                    rawTransaction,
                    createEip155SignatureData(
                        combinedSignatureData,
                        chainId
                    )
                )
            )
        ).send().transactionHash
    }

    fun getReceipt(txHash: String): TransactionReceipt? {
        return web3j.ethGetTransactionReceipt(txHash).send().transactionReceipt.orElse(null)
            .also { println(message = "Receipt = $it") }
    }

    // publicKey를 BouncyCastle의 ECPublicKeyParameters로 변환
    private fun convertPublicKey(publicKey: BigInteger): ECPublicKeyParameters {
        val curve = ecParams.curve

        return ECPublicKeyParameters(
            curve.createPoint(
                publicKey.shiftRight(256), // Public key 상위 256비트는 X 좌표
                publicKey.and(
                    BigInteger(
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                        16
                    )
                ) // Public key 하위 256비트는 Y 좌표
            ),
            ECDomainParameters(curve, ecParams.g, ecParams.n, ecParams.h)
        )
    }

    private fun combineShares(partialS: List<BigInteger>, xValues: List<BigInteger>): BigInteger {
        return partialS
            .zip(other = calculateLagrangeCoefficients(xValues = xValues)) // 라그랑주 보간법을 사용하여 x-좌표에 대응하는 라그랑주 계수 계산
            .fold(initial = BigInteger.ZERO) { acc, (partial, coeff) ->
                acc.add(partial.multiply(coeff).mod(prime)).mod(prime)
            } // (acc += 서명 값 x 라그랑주 계수 mod prime) mod prime
    }

    // 라그랑주 보간법 = 주어진 n개의 점을 지나는 다항식을 구하는 방법
    private fun calculateLagrangeCoefficients(xValues: List<BigInteger>): List<BigInteger> {
        return xValues.map { xi -> // 각 x_i에 대한 라그랑주 계수 계산
            xValues.fold(initial = BigInteger.ONE) { acc, xj ->
                if (xi != xj) acc.multiply(xj).mod(prime)
                    .multiply((xj - xi).modInverse(prime).mod(prime)).mod(prime)
                else acc
            }
        }
    }
}