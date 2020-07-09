<?php


namespace Phore\ASN;


abstract class DerUnpacker
{
    public static function unpack(string $derEncodedString) : array
    {
        $tlv = self::getTlv($derEncodedString);

        //echo "\nASN-Type: x" . $tlv['type'] .", Length: ". $tlv['length'] . "\n";
        print_r($tlv);

        switch ($tlv['type']) {
            case Asn1DerTypes::SEQUENCE:
                return ["x30" => self::unpackSequence($tlv)];
                //return ["x30" => self::unpack($tlv['value'])];
            case Asn1DerTypes::OBJECT_IDENTIFIER:
                return ["x06" => self::unpackObjectIdentifier($tlv['value'])];
            case Asn1DerTypes::NULL:
                return ["x05" => null];
            default:
                return [];
        }
    }

    private static function unpackObjectIdentifier(string $oidHex) : string
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

        while(!empty($bytes)) {
            $byte = array_shift($bytes);
            $intVal = self::hexToInt($byte);
            if($intVal < 128) {
                $oidParts[] = $intVal;
            } else {
                $bin = decbin($intVal);
                $num = (string) bindec(substr($bin, 3, 4));
                $fistBitOfSecondByte = substr($bin, -1, 1);
                $secondByteOffset = 16;
                if(substr($bin, -1, 1) == 0)
                    $secondByteOffset = 0;
                $byte = array_shift($bytes);
                $num .= (string) ($secondByteOffset + self::hexToInt("0" . substr($byte, 0,1)));
                $num .= (string) self::hexToInt("0" . substr($byte, 1,2));
                $oidParts[] = self::hexToInt($num);
            }
        }
        $oid = implode(".", $oidParts);
        return $oid;
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
            echo "lOl: " . $lengthOfLength;
            $length = self::hexToInt(substr($hex, 4, $lengthOfLength));
            $tlv['length'] = $length;
            $tlv['value'] = substr($hex, 4+$lengthOfLength, $length);
            $tlv['rest'] = substr($hex, 4+$lengthOfLength+$length);

        }
        return $tlv;
    }

    public static function decodeLength(string $hex)
    {
    }

    private static function hexToInt(string $hex)
    {
        return hexdec($hex);
    }

}
