import org.web3j.crypto.Keys
import kotlin.test.Test
import kotlin.test.assertTrue

class GG18ProtocolTest {
    @Test
    fun `공동서명 생성 및 검증`() {
        // given
        val threshold = 3
        val gg18 = GG18Protocol(numberOfParticipants = threshold)
        val keyPair = Keys.createEcKeyPair() // Web3j's EC key pair generation
        val secret = keyPair.privateKey
        println(message = "비밀 키: $secret")

        val shares = SharmirSecretSharing(totalShares = 5, threshold = threshold).splitKey(secret = secret)
        print(message = "비밀 조각:")
        shares.forEachIndexed { index, (x, y) -> println(message = "사용자 ${index + 1} = x: $x, y: $y") }

        val message = "Shamir Secret Sharing ECDSA Test".toByteArray()  // 서명을 위한 메시지
        val combinedSignature = gg18.signWithLagrange(
            shares = shares.shuffled().take(n = threshold), // 임계 값 만큼의 share를 랜덤하게 가져 옴
            message = message
        ) // 공동 서명을 통해 서명 생성
        println(message = "결합된 서명: r = ${combinedSignature.first}, s = ${combinedSignature.second}")

        // when
        val isSignatureValid = gg18.verifyCombinedSignature(publicKey = keyPair.publicKey, message = message, signature = combinedSignature) // 공통 공개키를 통한 서명 값 검증

        // then
        assertTrue(actual = isSignatureValid, message = "서명 검증 실패")
    }
}
