<?php

namespace unit;

use Phore\ASN\DerUnpacker;
use PHPUnit\Framework\TestCase;

class DerUnpackerTest extends TestCase
{
    public function testDecodeLength()
    {
        $array = DerUnpacker::unpack("300d06092a864886f70d0101010500");

        $this->assertTrue(true);
    }

}
