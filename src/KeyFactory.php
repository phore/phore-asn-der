<?php


namespace Phore\ASN;


use Phore\ASN\KeyFormats\Jwk;
use Phore\ASN\KeyFormats\KeyFormat;
use Phore\ASN\KeyFormats\Pem;
use UnexpectedValueException;

class KeyFactory
{
    /**
     * @param string $keyString Can be any PEM or JWK formatted private or public key of any PKCS-family
     * @param string $keyFormat KeyFormat::PEM or KeyFormat::JWK. If empty it will try to auto detect format
     * @return PkcsKey Returns a PkcsKey object of the appropriate type
     * @throws \Exception
     */
    public static function loadKey(string $keyString, string $keyFormat = "") : PkcsKey {
        // decode format
        switch ($keyFormat) {
            case "":
                return self::loadKey($keyString, self::detectFormat($keyString));
                break;
            case KeyFormat::PEM:
                return Pem::getPkcsKey($keyString);
                break;
            case KeyFormat::JWK:
                return Jwk::getPkcsKey($keyString);
                break;
            default:
                throw new UnexpectedValueException("Unknown key format: '$keyFormat'");
        }
    }

    public static function detectFormat(string $keyString) : string {
        //TODO: Implement some regex format detection
        return KeyFormat::PEM;
    }

}


