import dkg.PassiveSecurityDKGProtocol
import sharing.ShamirSecretSharing
import kotlin.test.Test
import kotlin.test.assertTrue

class DKGProtocolTest {
    @Test
    fun `난수 생성 및 개인키 추출`() {
        // given
        val totalParticipants = 5
        val threshold = 3
        val sss = ShamirSecretSharing(totalShares = totalParticipants, threshold = threshold)
        val dkg = PassiveSecurityDKGProtocol(totalParticipants = totalParticipants)
        // 난수 쉐어 생성 및 공유
        (1..totalParticipants)
            .map { dkg.generateRandomNumber(participantId = it) }
            .forEach { participant ->
                val participantId = participant.id
                val randomNumber = participant.randomNumber
                println(message = "참여자 ${participant.id} 가 생성한 난수: $randomNumber")
                // 난수 분할 (SSS 방식) / 난수를 분실해도 SSS 방식을 통해 t개의 난수 쉐어를 통해 난수를 복원할 수 있음
                val shares = sss.splitKey(secret = randomNumber)
                // 분할된 난수 쉐어들을 각 참여자에게 할당
                shares.forEach { share ->
                    dkg.sharePartitionedRandomNumber(participantId = participantId, share = share)
                }
                println(message = "참여자 $participantId 가 분할한 쉐어들: ${shares.map { it.y }}")
            }

        // 최종 쉐어를 이용하여 비밀키 복원
        val finalReconstructedShares = dkg.getAllFinalShares()

        // when
        // 최종적으로 비밀키를 복원 / 난수 쉐어의 임계 값을 3으로 하여 생성하였으므로 3개 이상의 최종 쉐어가 필요
        val reconstructedSecret1 = sss.reconstructKey(
            subsetOfShares = finalReconstructedShares.shuffled().take(n = threshold)
                .also { println(message = "Shares: $it") }
        )
        val reconstructedSecret2 = sss.reconstructKey(
            subsetOfShares = listOf(
                dkg.getFinalShare(participantId = 1),
                dkg.getFinalShare(participantId = 3),
                dkg.getFinalShare(participantId = 4)
            ).also { println("Shares: $it") })
        val reconstructedSecret3 = sss.reconstructKey(
            subsetOfShares = finalReconstructedShares.shuffled().take(n = 5)
                .also { println("Shares: $it") }
        )

        // then
        assertTrue(
            actual = reconstructedSecret1 == reconstructedSecret2 && reconstructedSecret2 == reconstructedSecret3,
            message = "비밀키 불일치"
        )
    }
}