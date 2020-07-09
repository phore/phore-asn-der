<?php


namespace Phore\ASN;


abstract class PemFormatHelper
{
    public static function pemEncodeKey(string $derEncodedKey, string $label) : string
    {
        $header = "-----BEGIN {$label}-----\n";
        $footer = "-----END {$label}-----\n";
        $base64Key = base64_encode(hex2bin($derEncodedKey));
        $data = chunk_split($base64Key,64, "\n");
        return $header . $data . $footer;
    }

}
