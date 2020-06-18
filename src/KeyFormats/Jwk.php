<?php


namespace Phore\ASN\KeyFormats;


use InvalidArgumentException;
use Phore\ASN\KeyTypes\RsaPrivateKey;
use Phore\ASN\KeyTypes\RsaPublicKey;
use Phore\ASN\PkcsKey;
use UnexpectedValueException;

class Jwk implements KeyFormat
{

    public static function getPkcsKey(string $keyString): PkcsKey
    {
        $jwk = json_decode($keyString, true);
        $keyType = phore_pluck('kty', $jwk, new \Exception("Invalid JWK - Key Type ('kty') missing"));
        if(key_exists('d', $jwk)) {
            //EC and RSA both hold a 'd' parameter in private keys
            $private = true;
        } else if(!key_exists('k', $jwk)) {
            //only oct (symmetric keys) have a k value. if it's not present, we can assume an EC or RSA public key
            $private = false;
        }
        switch ($keyType) {
            case 'RSA':
                if($private)
                    return new RsaPrivateKey(
                        base64_decode($jwk["n"]),
                        base64_decode($jwk["d"]),
                        base64_decode($jwk["e"]),
                        base64_decode($jwk["p"]),
                        base64_decode($jwk["q"]),
                        base64_decode($jwk["dp"]),
                        base64_decode($jwk["dq"]),
                        base64_decode($jwk["qi"])
                    );
                return new RsaPublicKey( base64_decode($jwk["n"]), base64_decode($jwk["e"]));
            case 'EC':
                throw new InvalidArgumentException("Key Type currently not supported");
            case 'oct':
                throw new InvalidArgumentException("Key Type currently not supported");
            default:
                throw new UnexpectedValueException("Unknown Key Type");
        }
    }

    public static function getKeyString(string $keyType, bool $privacy, $params): string
    {
        $jwk['kty'] = $keyType;
        $jwk += $params;
        return json_encode($jwk);
    }
}
