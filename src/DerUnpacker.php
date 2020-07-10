<?php


namespace Phore\ASN;


abstract class DerUnpacker
{
    public static function unpack(string $derEncodedString) : array
    {
        $tlv = self::getTlv($derEncodedString);

        switch ($tlv['type']) {
            case Asn1DerTypes::SEQUENCE:
                return ["x30" => self::unpackSequence($tlv)];
            case Asn1DerTypes::OBJECT_IDENTIFIER:
                return ["x06" => self::unpackObjectIdentifier($tlv['value'])];
            case Asn1DerTypes::NULL:
                return ["x05" => null];
            case Asn1DerTypes::BIT_STRING:
                return ["x03" => self::unpackBitString($tlv['value'])];
            case Asn1DerTypes::INTEGER:
                return ["x02" => self::unpackInteger($tlv['value'])];
            default:
                return ['UNKNOWN TYPE' => $tlv['type']];
        }
    }

    public static function unpackBitString(string $bitStringHex) : string
    {
        $unusedBits = hexdec(substr($bitStringHex, 0, 2));
        return substr($bitStringHex, 2, strlen($bitStringHex)-2-$unusedBits);
    }

    public static function unpackObjectIdentifier(string $oidHex) : string
    {
        $oidParts = [];
        $bytes = str_split($oidHex, 2);
        $firstByte = array_shift($bytes);
        $intVal = self::hexToInt($firstByte);
        $secondInt = $intVal%40;
        $firstInt = 0;
        while($intVal > 40) {
            $firstInt++;
            $intVal /=40;
        }
        $oidParts[] = (string) $firstInt;
        $oidParts[] = (string) $secondInt;

        $longIntBits = "";
        foreach($bytes as $byte) {
            $int = hexdec($byte);
            if($int < 128) {
                $bits = $longIntBits . str_pad(decbin($int), 7, '0', STR_PAD_LEFT);
                $oidParts[] = bindec($bits);
                $longIntBits = "";
            } else {
                $longIntBits .= substr(decbin($int), 1, 7);
            }
        }
        return implode(".", $oidParts);
    }

    private static function unpackSequence($sequenceTlv) :  array
    {
        $tlv = self::getTlv($sequenceTlv['value']);
        $rest = $tlv['rest'];
        $sequence = [];
        $sequence[] = self::unpack($sequenceTlv['value']);
        while(strlen($rest) > 0) {
            $tlv = self::getTlv($rest);
            $sequence[] = self::unpack($rest);
            $rest = $tlv['rest'];
        }
        return $sequence;
    }

    private static function getTlv(string $hex) : array
    {
        $tlv['type'] = substr($hex, 0, 2);
        $length = self::hexToInt(substr($hex, 2, 2));
        if($length < 128) {
            $tlv['length'] = $length;
            $tlv['value'] = substr($hex, 4, 2*$length);
            $tlv['rest'] = substr($hex, 4+2*$length);
        } else {
            $lengthOfLength = ($length - 128)*2;
            $length = self::hexToInt(substr($hex, 4, $lengthOfLength)); // length in byte
            $tlv['length'] = $length;
            $tlv['value'] = substr($hex, 4+$lengthOfLength, $length*2);
            $tlv['rest'] = substr($hex, 4+$lengthOfLength+$length*2);

        }
        return $tlv;
    }

    private static function hexToInt(string $hex)
    {
        return hexdec($hex);
    }

    private static function unpackInteger(string $intHex)
    {
        if(hexdec(substr($intHex, 0, 2)) === 0)
            $intHex = substr($intHex, 2);
        return $intHex;
    }

}
