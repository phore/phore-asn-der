<?php


namespace Phore\ASN;


use Phore\ASN\KeyFormats\KeyFormat;
use Phore\ASN\KeyFormats\Pem;

abstract class PkcsKey
{
    public const PRIVATE = true;
    public const PUBLIC = false;

    public const RSA = 'RSA';
    public const EC = 'EC';

    /**
     * @var bool true if Private Key, false if Public Key
     */
    protected $private;
    /**
     * @var string PKCS family identifier
     */
    protected $keyType;

    public abstract function exportPem() : string;
    public abstract function exportJwk() : string;

}
