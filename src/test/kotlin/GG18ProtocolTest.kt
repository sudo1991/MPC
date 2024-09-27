import ECDSAValues.prime
import abc.ethereum.EthereumAbi
import abc.ethereum.EthereumPrivateKey
import abc.ethereum.EthereumWallet
import abc.ethereum.contract.invocation.AbiBaseTransactionInvocationChain
import abc.ethereum.contract.invocation.EthereumInvocationContext
import abc.ethereum.contract.invocation.EthereumInvocationRequest
import abc.ethereum.contract.invocation.InvocationTarget
import com.esaulpaugh.headlong.abi.Tuple
import gg18.GG18Protocol
import gg18.SignatureFragment
import org.web3j.crypto.Hash
import org.web3j.crypto.Keys
import org.web3j.crypto.RawTransaction
import org.web3j.crypto.TransactionEncoder.encode
import org.web3j.protocol.core.DefaultBlockParameterName
import org.web3j.tx.gas.StaticGasProvider
import shamir.ShamirSecretSharing
import java.lang.Thread.sleep
import java.math.BigInteger
import java.security.SecureRandom
import java.util.*
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class GG18ProtocolTest {
    private val itemStoreAbi = javaClass.getResourceAsStream("/ethereum/contracts/ItemStore.json")!!
        .use { input -> EthereumAbi(inputStream = input) }
    private val threshold = 3
    private val keyPair = Keys.createEcKeyPair() // Web3j's EC key pair generation
    private val secret = keyPair.privateKey
    private val publicKey = keyPair.publicKey
    private val walletAddress = "0x${Keys.getAddress(publicKey)}"
    private val chainId = 1337L
    private val shares =
        ShamirSecretSharing(totalShares = 5, threshold = threshold).splitKey(secret = secret)

    private val wallet by lazy {
        EthereumWallet(
            endpoint = "https://quorum.ledgermaster.kr/",
            privateKey = EthereumPrivateKey(keyPair = keyPair)
        )
            .apply { gasProvider = StaticGasProvider(BigInteger.ZERO, 100_000.toBigInteger()) }
    }
    private val storeAddress by lazy {
        wallet.deploy(bytecode = itemStoreAbi.getBytecode(), chainId = chainId)
            .also { println(message = "Contract deployed: $it") }
    }
    private val fee = wallet.getFee(address = storeAddress)

    @BeforeTest
    fun beforeTest() {
        println(message = "Wallet address: $walletAddress, Private key: $secret, Public key: $publicKey")
        shares.forEachIndexed { index, (x, y) -> println(message = "사용자 ${index + 1} = x: $x, y: $y") }
    }

    @Test
    fun `공동서명 생성 및 검증`() {
        // given
        val gg18 = GG18Protocol(
            message = Hash.sha3(encode(getRawTransaction(), chainId)),
            numberOfParticipants = threshold
        )
        // 참가자들의 임시 키(nonce) 제출
        repeat(times = threshold) {
            gg18.addTemporaryKey(
                key = BigInteger(
                    prime.bitLength(),
                    SecureRandom()
                )
            )
        }
        // 각 참가자가 자신의 x 값과 조각 서명 값을 제출
        shares.shuffled().take(n = threshold)
            .forEach {
                gg18.addSignatureFragment(
                    signatureFragment = SignatureFragment(
                        x = it.x,
                        s = gg18.calculateS(gg18.r.multiply(it.y))
                    )
                )
            }
        val combinedSignatureData =
            gg18.signWithLagrange(publicKey = publicKey) // 조각 서명을 합하여 최종 서명 생성 후 서명

        // when
        val isSignatureValid = gg18.verifyCombinedSignature(
            publicKey = publicKey,
            combinedSignatureData = combinedSignatureData
        ) // 공통 공개키를 통한 서명 값 검증

        // then
        assertTrue(actual = isSignatureValid, message = "서명 검증 실패")
    }

    @Test
    fun `트랜잭션 전송 및 receipt 조회`() {
        // given
        val rawTransaction = getRawTransaction()
        val gg18 = GG18Protocol(
            message = Hash.sha3(encode(rawTransaction, chainId)),
            numberOfParticipants = threshold
        )
        // 참가자들의 임시 키(nonce) 제출
        repeat(times = threshold) {
            gg18.addTemporaryKey(
                key = BigInteger(
                    prime.bitLength(),
                    SecureRandom()
                )
            )
        }
        // 각 참가자가 자신의 x 값과 조각 서명 값을 제출
        shares.shuffled().take(n = threshold)
            .forEach {
                gg18.addSignatureFragment(
                    signatureFragment = SignatureFragment(
                        x = it.x,
                        s = gg18.calculateS(gg18.r.multiply(it.y))
                    )
                )
            }
        val txHash = gg18.sendTransaction(
            rawTransaction = rawTransaction,
            combinedSignatureData = gg18.signWithLagrange(publicKey = publicKey), // 조각 서명을 합하여 최종 서명 생성 후 서명
            chainId = chainId
        )
        sleep(3000L)

        // when
        val receipt = gg18.getReceipt(txHash = txHash)

        // then
        assertNotNull(actual = receipt, message = "Receipt is null")
        assertTrue(actual = walletAddress == receipt.from, message = "Transaction 검증 실패")
    }

    private fun getRawTransaction(): RawTransaction {
        return RawTransaction.createTransaction(
            wallet.web3j.ethGetTransactionCount(walletAddress, DefaultBlockParameterName.LATEST)
                .send().transactionCount,
            fee.price,
            fee.limit,
            storeAddress,
            AbiBaseTransactionInvocationChain(
                abi = itemStoreAbi.getFunction(
                    name = "addItem",
                    n = 1
                )!!
            ).doNext(
                context = EthereumInvocationContext(wallet = wallet),
                req = EthereumInvocationRequest(
                    privateKey = wallet.privateKey,
                    target = InvocationTarget(address = storeAddress, name = "addItem"),
                    arguments = listOf(
                        Tuple.of(
                            UUID.randomUUID().toString(),
                            Random.nextInt(0, 1000000001).toBigInteger()
                        )
                    ),
                    enableSendTransaction = false
                )
            ).returns as String
        )
    }
}
