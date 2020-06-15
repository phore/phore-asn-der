<?php


namespace Test;


use PHPUnit\Framework\TestCase;
use Phore\ASN\DerEncoder;
use Phore\FileSystem\PhoreFile;

class DerEncoderTest extends TestCase
{


    public function testDecoder()
    {
        $encoder = new DerEncoder();
        $mod = "suq/B8zKZZpwDcYL5Wu/jDZIZVnd7CmEAclJeuY4OOdd3JK73BkLdbI7HaTkEKrRsB8uz1RRH0fJ98GGrWPGhF37fLd3FDXJ8lgu+xa1SpqEEXSKMu+P0E8/iKb36lLP8dLqwoUe35fL1ErI+7/2mJjY8HWXwp/ZVEQ+HyJtHRpZwVTDY0tQzTFheNsNofpDlWt1X7XYheuX1wPE+OghrAFG/yx0O/nzN6ofLS7aYdE3Iwo6gWpCkIdsV9Y8171BgGwQ67hGMjmCUolFpg98TP3pg9V1m8cXWcZvysiKQxGNl3/ch22pKM9CjlPkCyDcU19aw3B1CBg1P6Jjeq53NyCkK+V5sr/RtwN1YA8HQTXDWqNysYUISfxioBks+hm6EyGX5AzQ6p3Pl7rOfISIi548EHzJTJtYIZi/uXaJ0XJwmhKR9h9K/3abMQ1VtLFEpvGDcQddGS+7UZrLzAPFGNzocv0Um30u4WDhOFGKA5LKftF4sPb8pgDCorbD4nMRh1NZO5FihkBMWRonR2BCYRoKjDuWrU5dfL8j/3wPqYajBGwyKs7APLjUpTe5yaN6EBbF0cvI+/6qSTD5qKyvJsZRkaJbMBTeqFst4Fff7FRKs7L+TWwzecBqCTVn+IsUn0JfqY4SN4HhjrVtzJHrVn+Dz6po8A3P9C7hJRfQCw0=";
        $exp = "AQAB";
        $pemPublic = $encoder->getPemPublicKeyFromModExp($mod, $exp);
        $this->assertIsString($pemPublic);
        $this->assertEquals($pemPublic, phore_file("file://".__DIR__."/mock_secrets/public-key-rsa4096.pem")->get_contents());
    }
}