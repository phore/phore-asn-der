<?php


namespace Phore\ASN;


class DerDecoder
{
    public function getModExp(string $pemKey)
    {
        $keyDetails = $this->getKeyDetails($pemKey);
        switch ($keyDetails['type']) {
            case OPENSSL_KEYTYPE_RSA:
                $key = [
                    "mod" => base64_encode($keyDetails["rsa"]["n"]),
                    "exp" => base64_encode($keyDetails["rsa"]["e"])
                ];
                break;
            case OPENSSL_KEYTYPE_DSA:
            case OPENSSL_KEYTYPE_DH:
            case OPENSSL_KEYTYPE_EC:
                break;
            default:
                return [];

        }
        return $key;
    }

    private function getKeyDetails(string $pemKey)
    {
        $privateKey = openssl_pkey_get_private($pemKey);
        return openssl_pkey_get_details($privateKey);
    }
}
