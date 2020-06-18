<?php


namespace Phore\ASN\KeyFormats;


use Phore\ASN\PkcsKey;

interface KeyFormat
{
    public const PEM = 'PEM';
    public const JWK = 'JWK';

//    public function getLabel(); // Returns whether the key is public or private
//    public function getKeyType(); // Returns the KeyType, that is the Family of Algorithms
    public static function getPkcsKey(string $keyString) : PkcsKey;

    public static function getKeyString(string $keyType, bool $privacy, $params) : string;

}
