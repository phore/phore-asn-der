<?php


use Phore\ASN\KeyFactory;
use Phore\ASN\KeyFormats\KeyFormat;
use Phore\ASN\KeyTypes\RsaPrivateKey;
use Phore\ASN\KeyTypes\RsaPublicKey;
use Phore\ASN\PkcsKey;
use PHPUnit\Framework\TestCase;

class KeyFactoryTest extends TestCase
{

    public function testLoadAndExportPemRsaPublicKey()
    {
        $keyString = phore_file(__DIR__."/mock_secrets/public-key-rsa4096.pem")->get_contents();
        $key = KeyFactory::loadKey($keyString, KeyFormat::PEM);
        $this->assertInstanceOf(RsaPublicKey::class, $key);

        $pemKey = $key->exportPem();

        $this->assertEquals($keyString, $pemKey);

        $jwkArray = json_decode($key->exportJwk(), true);
        $this->assertEquals( PkcsKey::RSA, $jwkArray['kty']);
    }

    public function testLoadPemRsaPrivateKeyExportJwk()
    {
        $keyString = phore_file(__DIR__."/mock_secrets/private-key-rsa4096.pem")->get_contents();
        $key = KeyFactory::loadKey($keyString, KeyFormat::PEM);
        $this->assertInstanceOf(RsaPrivateKey::class, $key);

        $jwkExport = json_decode($key->exportJwk(), true);
        $jwkFile = json_decode(phore_file(__DIR__."/mock_secrets/private-key-rsa4096.jwk")->get_contents(), true);

        $this->assertEquals( $jwkFile, $jwkExport);
    }

    public function testLoadJwkRsaPublicKeyExportPem()
    {
        $jwkString = phore_file(__DIR__."/mock_secrets/public-key-rsa4096.jwk")->get_contents();
        $key = KeyFactory::loadKey($jwkString, KeyFormat::JWK);
        $this->assertInstanceOf(RsaPublicKey::class, $key);

        $pemExport = $key->exportPem();
        $pemFile = phore_file(__DIR__."/mock_secrets/public-key-rsa4096.pem")->get_contents();

        $this->assertEquals( $pemFile, $pemExport);

    }

    public function testDetectFormat()
    {
        $jwkString = phore_file(__DIR__."/mock_secrets/public-key-rsa4096.jwk")->get_contents();
        $this->assertEquals(KeyFormat::JWK, KeyFactory::detectFormat($jwkString));

        $pemString = phore_file(__DIR__."/mock_secrets/public-key-rsa4096.pem")->get_contents();
        $this->assertEquals(KeyFormat::PEM, KeyFactory::detectFormat($pemString));
    }

}


