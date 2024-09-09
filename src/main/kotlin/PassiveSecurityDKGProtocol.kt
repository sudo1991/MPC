import java.math.BigInteger
import java.security.SecureRandom

class PassiveSecurityDKGProtocol(val totalParticipants: Int) {
    private val random = SecureRandom()
    private val allShares = Array(size = totalParticipants) { mutableListOf<Pair<Int, BigInteger>>() }
    private val finalShares by lazy {
        val _finalShares = Array(totalParticipants) { BigInteger.ZERO }
        // 각 참여자가 공유 받은 쉐어들을 더해 최종 쉐어 도출
        for (i in 0 until totalParticipants) {
            allShares[i].forEach { share ->
                _finalShares[i] = _finalShares[i].add(share.second)
            }
        }
        _finalShares
    }

    fun generateRandomNumber(participantId: Int): Participant {
        return Participant(id = participantId, randomNumber = BigInteger(256, random))
    }

    fun sharePartitionedRandomNumber(participantId: Int, share: Share) {
        allShares[(share.x - BigInteger.ONE).toInt()].add(Pair(participantId, share.y))
    }

    fun getAllFinalShares(): List<Share> {
        return finalShares.mapIndexed { index, finalShare ->
            Share((index + 1).toBigInteger(), finalShare)
        }
    }

    fun getFinalShare(participantId: Int): Share {
        return Share((participantId + 1).toBigInteger(), finalShares[participantId])
    }
}