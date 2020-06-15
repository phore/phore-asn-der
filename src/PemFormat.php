<?php


namespace Phore\ASN;


abstract class PemFormat
{
    protected $label;
    protected $algorithmIdentifier;
    protected $derEncodedData = "";

    public function __toString()
    {
        $header = "-----BEGIN {$this->label}-----\n";
        $footer = "-----END {$this->label}-----\n";
        $base64Key = $this->hexToBase64($this->derEncodedData);
        $data = chunk_split($base64Key,64, "\n");
        return $header . $data . $footer;
    }


    protected function base64toHex(string $base64String) : String
    {
        return bin2hex(base64_decode($base64String));
    }

    protected function hexToBase64(string $hexString) : String
    {
        return base64_encode(hex2bin($hexString));
    }

}
