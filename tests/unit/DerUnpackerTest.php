<?php

namespace unit;

use Phore\ASN\Asn1DerTypes;
use Phore\ASN\DerUnpacker;
use PHPUnit\Framework\TestCase;

class DerUnpackerTest extends TestCase
{
    public function testDecodeOid()
    {
        $oid = DerUnpacker::unpackObjectIdentifier("2a864886f70d010101");
        $this->assertEquals("1.2.840.113549.1.1.1", $oid);
    }

    public function testDecodePemOidSequence()
    {
        $result = DerUnpacker::unpack("30820222300d06092a864886f70d01010105000382020f003082020a0282020100b2eabf07ccca659a700dc60be56bbf8c36486559ddec298401c9497ae63838e75ddc92bbdc190b75b23b1da4e410aad1b01f2ecf54511f47c9f7c186ad63c6845dfb7cb7771435c9f2582efb16b54a9a8411748a32ef8fd04f3f88a6f7ea52cff1d2eac2851edf97cbd44ac8fbbff69898d8f07597c29fd954443e1f226d1d1a59c154c3634b50cd316178db0da1fa43956b755fb5d885eb97d703c4f8e821ac0146ff2c743bf9f337aa1f2d2eda61d137230a3a816a4290876c57d63cd7bd41806c10ebb846323982528945a60f7c4cfde983d5759bc71759c66fcac88a43118d977fdc876da928cf428e53e40b20dc535f5ac370750818353fa2637aae773720a42be579b2bfd1b70375600f074135c35aa372b1850849fc62a0192cfa19ba132197e40cd0ea9dcf97bace7c84888b9e3c107cc94c9b582198bfb97689d172709a1291f61f4aff769b310d55b4b144a6f18371075d192fbb519acbcc03c518dce872fd149b7d2ee160e138518a0392ca7ed178b0f6fca600c2a2b6c3e273118753593b916286404c591a27476042611a0a8c3b96ad4e5d7cbf23ff7c0fa986a3046c322acec03cb8d4a537b9c9a37a1016c5d1cbc8fbfeaa4930f9a8acaf26c65191a25b3014dea85b2de057dfec544ab3b2fe4d6c3379c06a093567f88b149f425fa98e123781e18eb56dcc91eb567f83cfaa68f00dcff42ee12517d00b0d0203010001");
        //print_r($result);
        $expected = [
            'x'.Asn1DerTypes::SEQUENCE => [
                [
                    'x'.Asn1DerTypes::SEQUENCE => [
                        ['x'.Asn1DerTypes::OBJECT_IDENTIFIER => "1.2.840.113549.1.1.1"],
                        ['x'.Asn1DerTypes::NULL => null]
                    ]
                ],
                [
                    'x'.Asn1DerTypes::BIT_STRING => "3082020a0282020100b2eabf07ccca659a700dc60be56bbf8c36486559ddec298401c9497ae63838e75ddc92bbdc190b75b23b1da4e410aad1b01f2ecf54511f47c9f7c186ad63c6845dfb7cb7771435c9f2582efb16b54a9a8411748a32ef8fd04f3f88a6f7ea52cff1d2eac2851edf97cbd44ac8fbbff69898d8f07597c29fd954443e1f226d1d1a59c154c3634b50cd316178db0da1fa43956b755fb5d885eb97d703c4f8e821ac0146ff2c743bf9f337aa1f2d2eda61d137230a3a816a4290876c57d63cd7bd41806c10ebb846323982528945a60f7c4cfde983d5759bc71759c66fcac88a43118d977fdc876da928cf428e53e40b20dc535f5ac370750818353fa2637aae773720a42be579b2bfd1b70375600f074135c35aa372b1850849fc62a0192cfa19ba132197e40cd0ea9dcf97bace7c84888b9e3c107cc94c9b582198bfb97689d172709a1291f61f4aff769b310d55b4b144a6f18371075d192fbb519acbcc03c518dce872fd149b7d2ee160e138518a0392ca7ed178b0f6fca600c2a2b6c3e273118753593b916286404c591a27476042611a0a8c3b96ad4e5d7cbf23ff7c0fa986a3046c322acec03cb8d4a537b9c9a37a1016c5d1cbc8fbfeaa4930f9a8acaf26c65191a25b3014dea85b2de057dfec544ab3b2fe4d6c3379c06a093567f88b149f425fa98e123781e18eb56dcc91eb567f83cfaa68f00dcff42ee12517d00b0d0203010001"
                ]
            ]
        ];

        $this->assertEquals($expected, $result);

        $modExpSeq = DerUnpacker::unpack($result['x30'][1]['x03']);
        $mod = $modExpSeq['x30'][0]['x02'];
        $exp = $modExpSeq['x30'][1]['x02'];

        $modExpected = "00b2eabf07ccca659a700dc60be56bbf8c36486559ddec298401c9497ae63838e75ddc92bbdc190b75b23b1da4e410aad1b01f2ecf54511f47c9f7c186ad63c6845dfb7cb7771435c9f2582efb16b54a9a8411748a32ef8fd04f3f88a6f7ea52cff1d2eac2851edf97cbd44ac8fbbff69898d8f07597c29fd954443e1f226d1d1a59c154c3634b50cd316178db0da1fa43956b755fb5d885eb97d703c4f8e821ac0146ff2c743bf9f337aa1f2d2eda61d137230a3a816a4290876c57d63cd7bd41806c10ebb846323982528945a60f7c4cfde983d5759bc71759c66fcac88a43118d977fdc876da928cf428e53e40b20dc535f5ac370750818353fa2637aae773720a42be579b2bfd1b70375600f074135c35aa372b1850849fc62a0192cfa19ba132197e40cd0ea9dcf97bace7c84888b9e3c107cc94c9b582198bfb97689d172709a1291f61f4aff769b310d55b4b144a6f18371075d192fbb519acbcc03c518dce872fd149b7d2ee160e138518a0392ca7ed178b0f6fca600c2a2b6c3e273118753593b916286404c591a27476042611a0a8c3b96ad4e5d7cbf23ff7c0fa986a3046c322acec03cb8d4a537b9c9a37a1016c5d1cbc8fbfeaa4930f9a8acaf26c65191a25b3014dea85b2de057dfec544ab3b2fe4d6c3379c06a093567f88b149f425fa98e123781e18eb56dcc91eb567f83cfaa68f00dcff42ee12517d00b0d";
        $expExpected = "010001";
        $this->assertEquals($expected, $result);

        $keyPath = __DIR__ . "/../mockData/public-key-rsa4096.pem";
        $expectedKey = trim(file_get_contents($keyPath));

        $key = openssl_pkey_get_public($expectedKey);
        $keyDetails = openssl_pkey_get_details($key);

        $this->assertEquals(bin2hex($keyDetails["rsa"]["n"]), $mod);
        $this->assertEquals(bin2hex($keyDetails["rsa"]["e"]), $exp);
    }

    public function testUnpackUnknownType()
    {
        $result = DerUnpacker::unpack("99FF01");
        $expected = [
            'UNKNOWN TYPE' => 99
        ];
        $this->assertEquals($expected, $result);
    }

}
