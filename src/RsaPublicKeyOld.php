<?php


namespace Phore\ASN;


class RsaPublicKeyOld extends PemFormat
{
    private $modulusHex;
    private $exponentHex;

    public function __construct()
    {
        $this->label = "PUBLIC KEY";
        $this->algorithmIdentifier = "300d06092a864886f70d0101010500";
    }

    public function createFromPemPrivateKeyString(string $pemKey)
    {
        $keyDetails = $this->getKeyDetails($pemKey);
        if($keyDetails['type'] !== OPENSSL_KEYTYPE_RSA) {
            throw new \Exception("Key type must be RSA");
        }
        $this->modulusHex = bin2hex($keyDetails["rsa"]["n"]);
        $this->exponentHex = bin2hex($keyDetails["rsa"]["e"]);
    }

    /**
     * @param string $modulus Base64-encoded binary representation of modulus
     * @param string $exponent Base64-encoded binary representation of exponent
     * @throws Exception When using unsupported key type
     */
    public function createFromModExpBase64(string $modulus, string $exponent)
    {
        $this->modulusHex = $this->base64toHex($modulus);
        $this->exponentHex = $this->base64toHex($exponent);
        $this->createFromModExpHex($this->modulusHex, $this->exponentHex);
    }

    /**
     * @param string $modulus hex representation of modulus
     * @param string $exponent hex representation of exponent
     * @throws Exception When using unsupported key type
     */
    public function createFromModExpHex(string $modulus, string $exponent)
    {
        $derMod = DerPacker::packUnsignedInt($modulus);
        $derExp = DerPacker::packUnsignedInt($exponent);
        $derModExp = DerPacker::packSequence($derMod, $derExp);
        $derPubKeyBitString = DerPacker::packBitString($derModExp, "00");
        $this->derEncodedData = DerPacker::packSequence($this->algorithmIdentifier, $derPubKeyBitString);
    }

    private function getKeyDetails(string $pemKey)
    {
        $privateKey = openssl_pkey_get_private($pemKey);
        return openssl_pkey_get_details($privateKey);
    }

    public function getModulusHex()
    {
        return $this->modulusHex;
    }

    public function getModulusBase64()
    {
        return $this->hexToBase64($this->modulusHex);
    }

    public function getExponentHex()
    {
        return $this->exponentHex;
    }

    public function getExponentBase64()
    {
        return $this->hexToBase64($this->exponentHex);
    }

}
