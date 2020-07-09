<?php


use Phore\ASN\DerPacker;
use PHPUnit\Framework\TestCase;

class DerPackerTest extends TestCase
{
    public function testEncodePositiveSignedInteger()
    {
        $hexInt = "07C3";
        $derString = DerPacker::packInt($hexInt);
        $this->assertEquals("020207C3", $derString);
    }

    public function testEncodeNegativeSignedInteger()
    {
        $hexInt = "FD0F"; // -753
        $derString = DerPacker::packInt($hexInt);
        $this->assertEquals("0202FD0F", $derString);
    }

    public function testEncodeNegativeUnsignedInteger()
    {
        $hexInt = "FD0F"; // 64783
        $derString = DerPacker::packUnsignedInt($hexInt);
        $this->assertEquals("020300FD0F", $derString);
    }


}
