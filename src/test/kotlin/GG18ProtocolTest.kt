import abc.ethereum.EthereumAbi
import abc.ethereum.EthereumPrivateKey
import abc.ethereum.EthereumWallet
import abc.ethereum.contract.invocation.AbiBaseTransactionInvocationChain
import abc.ethereum.contract.invocation.EthereumInvocationContext
import abc.ethereum.contract.invocation.EthereumInvocationRequest
import abc.ethereum.contract.invocation.InvocationTarget
import abc.util.orNull
import com.esaulpaugh.headlong.abi.Tuple
import org.web3j.crypto.Hash
import org.web3j.crypto.Keys
import org.web3j.crypto.RawTransaction
import org.web3j.crypto.Sign
import org.web3j.crypto.TransactionEncoder.createEip155SignatureData
import org.web3j.crypto.TransactionEncoder.encode
import org.web3j.protocol.core.DefaultBlockParameterName
import org.web3j.tx.gas.StaticGasProvider
import org.web3j.utils.Numeric.toHexString
import java.lang.Thread.sleep
import java.math.BigInteger
import java.util.*
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class GG18ProtocolTest {
    private val itemStoreAbi = javaClass.getResourceAsStream("/ethereum/contracts/ItemStore.json")!!
        .use { input -> EthereumAbi(inputStream = input) }

    private val wallet by lazy {
        EthereumWallet(
            endpoint = "https://quorum.ledgermaster.kr/",
            privateKey = EthereumPrivateKey(keyPair)
        )
            .apply { gasProvider = StaticGasProvider(BigInteger.ZERO, 100_000.toBigInteger()) }
    }
    private val storeAddress by lazy {
        wallet.deploy(bytecode = itemStoreAbi.getBytecode(), chainId = chainId)
            .also { println(message = "Contract deployed: $it") }
    }

    private val threshold = 3
    private val gg18 = GG18Protocol(numberOfParticipants = threshold)
    private val keyPair = Keys.createEcKeyPair() // Web3j's EC key pair generation
    private val secret = keyPair.privateKey
    private val walletAddress = "0x${Keys.getAddress(keyPair.publicKey)}"
    private val chainId = 1337L
    private val shares =
        SharmirSecretSharing(totalShares = 5, threshold = threshold).splitKey(secret = secret)
    private val fee = wallet.getFee(address = storeAddress)

    @BeforeTest
    fun beforeTest() {
        println(message = "Wallet address: $walletAddress, 비밀 키: $secret")
        print(message = "비밀 조각:")
        shares.forEachIndexed { index, (x, y) -> println(message = "사용자 ${index + 1} = x: $x, y: $y") }
    }

    @Test
    fun `공동서명 생성 및 검증`() {
        // given
        val message = Hash.sha3(encode(getRawTransaction(), chainId))
        val combinedSignatureData = getCombinedSignatureData(message = message)

        // when
        val isSignatureValid = gg18.verifyCombinedSignature(
            publicKey = keyPair.publicKey,
            message = message,
            combinedSignatureData = combinedSignatureData
        ) // 공통 공개키를 통한 서명 값 검증

        // then
        assertTrue(actual = isSignatureValid, message = "서명 검증 실패")
    }

    @Test
    fun `트랜잭션 전송 및 receipt 조회`() {
        // given
        val rawTransaction = getRawTransaction()
        val encodedTransaction = encode(rawTransaction, chainId)
        val combinedSignatureData =
            getCombinedSignatureData(message = Hash.sha3(encodedTransaction))
        val recoveredWalletAddress = "0x${
            Keys.getAddress(
                Sign.signedMessageToKey(
                    encodedTransaction,
                    combinedSignatureData
                )
            )
        }"
            .also { println("Recovered wallet address: $it") }
        val txHash = wallet.web3j.ethSendRawTransaction(
            toHexString(
                encode(
                    rawTransaction,
                    createEip155SignatureData(combinedSignatureData, chainId)
                )
            )
        ).send().transactionHash
        sleep(3000L)

        // when
        val receipt =
            wallet.web3j.ethGetTransactionReceipt(txHash).send().transactionReceipt.orNull()
                .also { println(message = "Receipt = $it") }

        // then
        assertNotNull(actual = receipt, message = "Receipt is null")
        assertTrue(
            actual = walletAddress == receipt.from && walletAddress == recoveredWalletAddress,
            message = "Transaction 검증 실패"
        )
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

    private fun getCombinedSignatureData(message: ByteArray): Sign.SignatureData {
        return gg18.signWithLagrange(
            shares = shares.shuffled().take(n = threshold), // 임계 값 만큼의 share를 랜덤하게 가져 옴
            message = message
        ) // 공동 서명을 통해 서명 생성
            .also { println("r = ${BigInteger(it.r)}, s = ${BigInteger(it.s)}, v = ${BigInteger(it.v)}") }
    }
}
