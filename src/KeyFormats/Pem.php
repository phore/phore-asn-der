<?php


namespace Phore\ASN\KeyFormats;


use Phore\ASN\KeyTypes\RsaPrivateKey;
use UnexpectedValueException;
use Phore\ASN\KeyTypes\RsaPublicKey;
use Phore\ASN\PkcsKey;

class Pem implements KeyFormat
{
    public static function getPkcsKey($pemKeyString): PkcsKey
    {
        if(self::isPrivate($pemKeyString)) {
            $key = openssl_pkey_get_private($pemKeyString);
            $keyDetails = openssl_pkey_get_details($key);
            switch ($keyDetails['type']) {
                case OPENSSL_KEYTYPE_RSA:
                    return new RsaPrivateKey(
                        $keyDetails["rsa"]["n"],
                        $keyDetails["rsa"]["d"],
                        $keyDetails["rsa"]["e"],
                        $keyDetails["rsa"]["p"],
                        $keyDetails["rsa"]["q"],
                        $keyDetails["rsa"]["dmp1"],
                        $keyDetails["rsa"]["dmq1"],
                        $keyDetails["rsa"]["iqmp"]
                    );
                case OPENSSL_KEYTYPE_DSA:
                case OPENSSL_KEYTYPE_DH:
                case OPENSSL_KEYTYPE_EC:
                    throw new \InvalidArgumentException("Key Type currently not supported");
                default:
                    throw new UnexpectedValueException("Unknown Key Type");
            }
        } else {
            $key = openssl_pkey_get_public($pemKeyString);
            $keyDetails = openssl_pkey_get_details($key);
            switch ($keyDetails['type']) {
                case OPENSSL_KEYTYPE_RSA:
                    return new RsaPublicKey($keyDetails["rsa"]["n"], $keyDetails["rsa"]["e"]);
                case OPENSSL_KEYTYPE_DSA:
                case OPENSSL_KEYTYPE_DH:
                case OPENSSL_KEYTYPE_EC:
                    throw new \InvalidArgumentException("Key Type currently not supported");
                default:
                    throw new UnexpectedValueException("Unknown Key Type");
            }
        }
    }

    public static function isPrivate($pemKeyString) : bool
    {
        if(!preg_match("/-{5}BEGIN (?:(RSA|EC) )?(PUBLIC|PRIVATE) KEY-{5}/", $pemKeyString, $matches)) {
            throw new UnexpectedValueException("Unknown key format");
        }
        if($matches[2] == "PRIVATE")
            return true;
        return false;
    }

    public static function getKeyString(string $keyType, bool $privacy, $derEncodedKey): string
    {
        $label = $privacy ? 'PRIVATE KEY' : 'PUBLIC KEY';
        $header = "-----BEGIN {$label}-----\n";
        $footer = "-----END {$label}-----\n";
        $base64Key = base64_encode(hex2bin($derEncodedKey));
        $data = chunk_split($base64Key,64, "\n");
        return $header . $data . $footer;
    }
}
