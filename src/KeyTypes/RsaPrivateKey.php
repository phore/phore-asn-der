<?php


namespace Phore\ASN\KeyTypes;


use InvalidArgumentException;
use Phore\ASN\KeyFormats\Jwk;
use Phore\ASN\PkcsKey;

class RsaPrivateKey extends PkcsKey
{
    private $privateExponent;
    private $modulus;
    private $publicExponent;
    private $primeP;
    private $primeQ;
    private $FirstFactorCrtExponent;
    private $SecondFactorCrtExponent;
    private $FirstCrtCoefficient;

    public function __construct(
        $modulus,
        $privateExponent,
        $publicExponent = null,
        $primeP = null,
        $primeQ = null,
        $FirstFactorCrtExponent = null,
        $SecondFactorCrtExponent = null,
        $FirstCrtCoefficient = null
    ) {
        $this->private = self::PUBLIC;
        $this->keyType = self::RSA;
        $this->modulus = $modulus;
        $this->privateExponent = $privateExponent;
        $this->publicExponent = $publicExponent;
        $this->primeP = $primeP;
        $this->primeQ = $primeQ;
        $this->FirstFactorCrtExponent = $FirstFactorCrtExponent;
        $this->SecondFactorCrtExponent = $SecondFactorCrtExponent;
        $this->FirstCrtCoefficient = $FirstCrtCoefficient;
    }

    public function exportPem(): string
    {
        // TODO: Implement exportPem() method.
        throw new InvalidArgumentException("currently not supported");
    }

    public function exportJwk(): string
    {
        $jwkParams = [
            'n' => base64_encode($this->modulus),
            'd' => base64_encode($this->privateExponent),
        ];
        if($this->publicExponent !== null)
            $jwkParams['e'] = base64_encode($this->publicExponent);
        if($this->primeP !== null)
            $jwkParams['p'] = base64_encode($this->primeP);
        if($this->primeQ !== null)
            $jwkParams['q'] = base64_encode($this->primeQ);
        if($this->FirstFactorCrtExponent !== null)
            $jwkParams['dp'] = base64_encode($this->FirstFactorCrtExponent);
        if($this->SecondFactorCrtExponent !== null)
            $jwkParams['dq'] = base64_encode($this->SecondFactorCrtExponent);
        if($this->FirstCrtCoefficient !== null)
            $jwkParams['qi'] = base64_encode($this->FirstCrtCoefficient);

        return Jwk::getKeyString($this->keyType, $this->private, $jwkParams);
    }
}
