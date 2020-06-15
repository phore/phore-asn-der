<?php


namespace Phore\ASN;


abstract class DerPacker
{

    /**
     * Packs a signed integer
     *
     * For example the hex value "8F" would be -113 as a signed int, but 143 as an unsigned int
     * @param string $hexInt
     * @return string
     */
    public static function packInt(string $hexInt) : string
    {
        return self::getTlv(Asn1DerTypes::INTEGER, $hexInt);
    }

    /**
     * Packs an unsigned integer
     *
     * For example the hex value "8F" would be -113 as a signed int, but 143 as an unsigned int
     * @param string $hexUint
     * @return string
     */
    public static function packUnsignedInt(string $hexUint) : string
    {
        $msb = substr($hexUint, 0, 1);
        if($msb > "7") {
            $hexUint = "00" . $hexUint;
        }
        return self::getTlv(Asn1DerTypes::INTEGER, $hexUint);
    }

    /**
     * Packs a bit string. This requires an extra byte, that determines the number of unused bits,
     * if the length of the bit string is not dividable by 8
     *
     * For example: The bit string '011010001' needs two bytes to be represented - 01101000 10000000 (hex 68 80)
     * Seven bytes at the end of the hex representation are unused, so the unusedBits byte would be '07'
     *
     * @param string $hexBitString
     * @param string $hexUnusedBits
     * @return string
     */
    public static function packBitString(string $hexBitString, string $hexUnusedBits) : string
    {
        return self::getTlv(Asn1DerTypes::BIT_STRING, $hexUnusedBits . $hexBitString);
    }

    /**
     * Packs one ore more DER-encoded elements into a sequence
     *
     * @param string ...$hexDerEncodedString
     * @return string
     */
    public static function packSequence(string ...$hexDerEncodedString) : string
    {
        $sequence = implode("", $hexDerEncodedString);
        return self::getTlv(Asn1DerTypes::SEQUENCE, $sequence);
    }

    /**
     * Get the TLV (Type, Length, Value) representation of the content
     *
     * @param string $type
     * @param string $content
     * @return string
     */
    public static function getTlv(string $type, string $content) :  string
    {
        $length = strlen($content)/2;
        $encodedLength = self::encodeLengthHex($length);
        return $type.$encodedLength.$content;
    }

    private static function encodeLengthHex(int $n) {
        if($n < 128) {
            return self::intToHex($n);
        } else {
            $nHex = self::intToHex($n);
            $lengthOfLengthByte = 128 + strlen($nHex)/2;
            return self::intToHex($lengthOfLengthByte) . $nHex;
        }
    }

    private static function intToHex(int $n) {
        $hex = dechex($n);
        if(strlen($hex)%2 === 1) {
            return "0".$hex;
        }
        return $hex;
    }

}
