import org.junit.jupiter.api.assertThrows
import org.web3j.crypto.Keys
import sharing.ShamirSecretSharing
import kotlin.test.Test
import kotlin.test.assertEquals

class ShamirSecretSharingTest {
    @Test
    fun `키 분할`() {
        // given
        val masterPrivateKey = Keys.createEcKeyPair().privateKey
        val totalShares = 5

        val sss = ShamirSecretSharing(
            totalShares = totalShares,
            threshold = 3
        ) // totalShares = 생성할 총 조각 수, threshold = 키를 재구성하는데 필요한 최소한의 조각 수
        // when
        val shares = sss.splitKey(secret = masterPrivateKey)

        // then
        assertEquals(
            expected = totalShares,
            actual = shares.size,
            message = "The total number of shares requested matches the number of shares returned."
        )
    }

    @Test
    fun `임계 값 보다 작은 수의 Share를 통한 키 재구성`() {
        // given
        val masterPrivateKey = Keys.createEcKeyPair().privateKey
        val threshold = 3
        val sss = ShamirSecretSharing(
            totalShares = 5,
            threshold = 3
        ) // totalShares = 생성할 총 조각 수, threshold = 키를 재구성하는데 필요한 최소한의 조각 수
        val shares = sss.splitKey(secret = masterPrivateKey)

        // when
        // then
        assertThrows<IllegalArgumentException> { sss.reconstructKey(subsetOfShares = shares.shuffled().subList(0, threshold - 1))  }
    }

    @Test
    fun `임계 값 만큼의 Share를 통한 키 재구성`() {
        // given
        val masterPrivateKey = Keys.createEcKeyPair().privateKey
        val threshold = 3
        val sss = ShamirSecretSharing(
            totalShares = 5,
            threshold = threshold
        ) // totalShares = 생성할 총 조각 수, threshold = 키를 재구성하는데 필요한 최소한의 조각 수

        val shares = sss.splitKey(secret = masterPrivateKey)

        // when
        val reconstructedKeyWith3Shares = sss.reconstructKey(subsetOfShares = shares.shuffled().subList(0, threshold))

        // then
        assertEquals(
            expected = masterPrivateKey,
            actual = reconstructedKeyWith3Shares,
            message = "The reconstructed key should match the original master key."
        )
    }
}