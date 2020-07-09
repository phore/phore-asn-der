<?php


use Phore\ASN\DerPacker;
use PHPUnit\Framework\TestCase;

class IntegrationTest extends TestCase
{
    public function testPackPublicRsa4096PemKey()
    {
        $keyPath = __DIR__ . "/mockData/public-key-rsa4096.pem";
        $expectedKey = trim(file_get_contents($keyPath));

        $key = openssl_pkey_get_public($expectedKey);
        $keyDetails = openssl_pkey_get_details($key);

        $oid = "300d06092a864886f70d0101010500";
        $derMod = DerPacker::packUnsignedInt(bin2hex($keyDetails["rsa"]["n"]));
        $derExp = DerPacker::packUnsignedInt(bin2hex($keyDetails["rsa"]["e"]));
        $derModExp = DerPacker::packSequence($derMod, $derExp);
        $derPubKeyBitString = DerPacker::packBitString($derModExp, "00");
        $derEncodedKey = DerPacker::packSequence($oid, $derPubKeyBitString);

        $label = 'PUBLIC KEY';
        $header = "-----BEGIN {$label}-----\n";
        $footer = "-----END {$label}-----\n";
        $base64Key = base64_encode(hex2bin($derEncodedKey));
        $data = chunk_split($base64Key,64, "\n");
        $keyString = trim($header . $data . $footer);

        $expectedKey = trim(file_get_contents($keyPath));
        $this->assertEquals($expectedKey, $keyString);
    }

}
