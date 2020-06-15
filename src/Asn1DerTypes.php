<?php


namespace Phore\ASN;


abstract class Asn1DerTypes
{
    public const BIT_STRING = "03";
    public const BOOLEAN = "01";
    public const INTEGER = "02";
    public const NULL = "05";
    public const OBJECT_IDENTIFIER = "06";
    public const OCTET_STRING = "04";
    /**
     * Basic Multilingual Plane of ISO/IEC/ITU 10646-1
     * represents unicode characters
     */
    public const BMP_STRING = "1E";
    /**
     * International ASCII characters (International Alphabet 5)
     */
    public const IA5_STRING = "16";
    /**
     * a-z, A-Z, ' () +,-.?:/= and SPACE
     */
    public const PRINTABLE_STRING = "13";
    public const UTF8_STRING = "0C";
    public const SEQUENCE = "30";
    public const SET = "31";

}
