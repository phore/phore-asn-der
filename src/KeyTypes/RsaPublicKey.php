<?php


namespace Phore\ASN\KeyTypes;


use Phore\ASN\DerPacker;
use Phore\ASN\KeyFormats\Jwk;
use Phore\ASN\KeyFormats\Pem;
use Phore\ASN\PkcsKey;

class RsaPublicKey extends PkcsKey
{
    private $exponent;
    private $modulus;

    public function __construct($modulus, $exponent)
    {
        $this->private = self::PUBLIC;
        $this->keyType = self::RSA;
        $this->exponent = $exponent;
        $this->modulus = $modulus;
    }

    public function exportPem() : string
    {
        //pack $exp, mod, alg, DER-Encode, add headers, return
        $oid = "300d06092a864886f70d0101010500";

        $derMod = DerPacker::packUnsignedInt(bin2hex($this->modulus));
        $derExp = DerPacker::packUnsignedInt(bin2hex($this->exponent));
        $derModExp = DerPacker::packSequence($derMod, $derExp);
        $derPubKeyBitString = DerPacker::packBitString($derModExp, "00");
        $derEncodedKey = DerPacker::packSequence($oid, $derPubKeyBitString);
        return Pem::getKeyString($this->keyType, $this->private, $derEncodedKey);

    }

    public function exportJwk(): string
    {
        $jwkParams = ['n' => base64_encode($this->modulus), 'e' => base64_encode($this->exponent)];
        return Jwk::getKeyString($this->keyType, $this->private, $jwkParams);
    }
}
