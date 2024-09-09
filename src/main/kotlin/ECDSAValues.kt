import org.web3j.crypto.Sign

object ECDSAValues {
    val ecParams = Sign.CURVE_PARAMS!!
    val prime = ecParams.n!!
}