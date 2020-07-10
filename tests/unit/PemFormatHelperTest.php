<?php

namespace unit;

use Phore\ASN\DerPacker;
use Phore\ASN\PemFormatHelper;
use PHPUnit\Framework\TestCase;

class PemFormatHelperTest extends TestCase
{
    public function testPackPublicRsa4096PemKey()
    {
        $keyPath = __DIR__ . "/../mockData/public-key-rsa4096.pem";
        $expectedKey = file_get_contents($keyPath);

        $key = openssl_pkey_get_public($expectedKey);
        $keyDetails = openssl_pkey_get_details($key);

        $oid = "300d06092a864886f70d0101010500";
        $derMod = DerPacker::packUnsignedInt(bin2hex($keyDetails["rsa"]["n"]));
        $derExp = DerPacker::packUnsignedInt(bin2hex($keyDetails["rsa"]["e"]));
        $derModExp = DerPacker::packSequence($derMod, $derExp);
        $derPubKeyBitString = DerPacker::packBitString($derModExp, "00");
        $derEncodedKey = DerPacker::packSequence($oid, $derPubKeyBitString);

        $label = 'PUBLIC KEY';

        $keyString = PemFormatHelper::pemEncodeKey($derEncodedKey, $label);

        $this->assertEquals($expectedKey, $keyString);
    }

}
