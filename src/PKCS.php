
class PkcsKey {

	protected $alg;
	protected $keyFormat;
	protected $keyString;

	public function toFormat(KeyFormat $format) {
		return $format->format($this->keyString);
	}

}

class PubKey extends PkcsKey {

	public function __construct(string $keyString, $keyFormat = "") {
		switch ($keyFormat) {
			case "":
				$this->detectFormat($keyString);
				break;
			case "PEM":
				$this->keyFormat = PEM;
				break;
			default:
				throw new Exception("Unknown Format");
		}
		$this->KeyString = $keyString;

	}

	private function detectFormat()
	{

	}

}


$pubKey = new PubKey($PemKeyFile);
$jwk = $pubKey->toFormat(JWK $jwk);


$pubKey = new PubKey($Jwk);
$jwk = $pubKey->toFormat(PEM $pem);

interface KeyFormat {
    public function format(string $keyString);
}

class Jwk implements KeyFormat {

	public function format(string $keyString) {
		return $keyString;
	}
}



Algorithmen
	RSA
        pub n,e;
        priv d,e;
	Ecliptic Curve
        pub x,y,q

Formate
	Pem#1
	Pem#8 !!
	JWK	!!
	OpenSSH


$pem = jwk2pem($jwk);
$jwk = pem2jwk($pem);


$pubKey = new PubKey($PemKeyFile);
$jwk = $pubKey->toFormat(JWK $jwk);


$pubKey = new PubKey($Jwk);
$jwk = $pubKey->toFormat(PEM $pem);


/**************************************************************/

interface Algorithmen {

}

class Rsa implements Algorithmen {
    // pub key immer aus
    private $n; // pub + priv
    private $e; // pub
    private $d; // priv
}

