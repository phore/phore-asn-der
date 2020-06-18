<?php


use Phore\ASN\KeyFactory;
use Phore\ASN\KeyFormats\KeyFormat;
use Phore\ASN\KeyTypes\RsaPrivateKey;
use Phore\ASN\KeyTypes\RsaPublicKey;
use PHPUnit\Framework\TestCase;

class KeyFactoryTest extends TestCase
{
    private static $keyFile_JWK_RSA_Public;
    private static $keyFile_JWK_RSA_Private;
    private static $keyFile_PEM_RSA_Public;
    private static $keyFile_PEM_RSA_Private;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        self::$keyFile_PEM_RSA_Public = phore_file(__DIR__."/mock_secrets/public-key-rsa4096.pem")->get_contents();
        self::$keyFile_PEM_RSA_Private = phore_file(__DIR__."/mock_secrets/private-key-rsa4096.pem")->get_contents();
        self::$keyFile_JWK_RSA_Public = phore_file(__DIR__."/mock_secrets/public-key-rsa4096.jwk")->get_contents();
        self::$keyFile_JWK_RSA_Private = phore_file(__DIR__."/mock_secrets/private-key-rsa4096.jwk")->get_contents();
    }

    public function testDetectFormat()
    {
        $this->assertEquals(
            KeyFormat::JWK,
            KeyFactory::detectFormat(self::$keyFile_JWK_RSA_Public)
        );

        $this->assertEquals(
            KeyFormat::PEM,
            KeyFactory::detectFormat(self::$keyFile_PEM_RSA_Public)
        );
    }

    public function testLoadPemRsaPublicExportAllFormats()
    {
        $key = KeyFactory::loadKey(self::$keyFile_PEM_RSA_Public);
        $this->assertInstanceOf(RsaPublicKey::class, $key);

        $jwkExport = json_decode($key->exportJwk(), true);
        $jwkFile = json_decode(self::$keyFile_JWK_RSA_Public, true);
        $this->assertEquals( $jwkFile, $jwkExport);

        $pemExport = $key->exportPem();
        $pemFile = self::$keyFile_PEM_RSA_Public;
        $this->assertEquals( $pemFile, $pemExport);
    }

    public function testLoadPemRsaPrivateExportAllFormats()
    {
        $key = KeyFactory::loadKey(self::$keyFile_PEM_RSA_Private);
        $this->assertInstanceOf(RsaPrivateKey::class, $key);

        $jwkExport = json_decode($key->exportJwk(), true);
        $jwkFile = json_decode(self::$keyFile_JWK_RSA_Private, true);
        $this->assertEquals( $jwkFile, $jwkExport);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("currently not supported");
        $pemExport = $key->exportPem();
//        $pemFile = self::$keyFile_PEM_RSA_Private;
//        $this->assertEquals( $pemFile, $pemExport);
    }

    public function testLoadJwkRsaPublicExportAllFormats()
    {
        $key = KeyFactory::loadKey(self::$keyFile_JWK_RSA_Public);
        $this->assertInstanceOf(RsaPublicKey::class, $key);

        $jwkExport = json_decode($key->exportJwk(), true);
        $jwkFile = json_decode(self::$keyFile_JWK_RSA_Public, true);
        $this->assertEquals( $jwkFile, $jwkExport);

        $pemExport = $key->exportPem();
        $pemFile = self::$keyFile_PEM_RSA_Public;
        $this->assertEquals( $pemFile, $pemExport);
    }

    public function testLoadJwkRsaPrivateExportAllFormats()
    {
        $key = KeyFactory::loadKey(self::$keyFile_JWK_RSA_Private);
        $this->assertInstanceOf(RsaPrivateKey::class, $key);

        $jwkExport = json_decode($key->exportJwk(), true);
        $jwkFile = json_decode(self::$keyFile_JWK_RSA_Private, true);
        $this->assertEquals( $jwkFile, $jwkExport);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("currently not supported");
        $pemExport = $key->exportPem();
//        $pemFile = self::$keyFile_PEM_RSA_Private;
//        $this->assertEquals( $pemFile, $pemExport);
    }
}


