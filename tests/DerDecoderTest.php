<?php


namespace Test;


use PHPUnit\Framework\TestCase;
use Phore\ASN\DerDecoder;

class DerDecoderTest extends TestCase
{


    public function testDecoder()
    {
        $decoder = new DerDecoder();
        $modexp = $decoder->getModExp("file://".__DIR__."/mock_secrets/private-key-rsa4096.pem");
        $this->assertEquals(2, count($modexp));
        $this->assertArrayHasKey("mod", $modexp);
        $this->assertArrayHasKey("exp", $modexp);
    }
}
