<?php
/**
 * This module is part of the project PHPhmac.
 *
 * This module is an PHP implementation of the HMAC algorithm described by the
 * standard <<Key hash message authentication code (HMAC) (FIPS PUB 198)>>.
 */

// List of internal block sizes of the hash algorithm in bytes.
const BLOCK_SIZES = [
    'md5' => 64,
    'sha1' => 64,
    'sha224' => 64,
    'sha256'=> 64,
    'sha384' => 128,
    'sha512' => 128,
    'sha3-224' => 144,
    'sha3-256' => 136,
    'sha3-384' => 104,
    'sha3-512' => 72
];


// All ASCII characters from 0 to 255
$ascii = null;
for ($code=0; $code < 256; $code++) {
    $ascii .= chr($code);
}

// $ipad and $opad were chosen in order to have an important Hamming distance.
$opad = null;
for ($code=0; $code < 256; $code++) {
    $opad .= chr($code ^ 0x5C);
}

$ipad = null;
for ($code=0; $code < 256; $code++) {
    $ipad .= chr($code ^ 0x36);
}

/**
 * Make the XOR between $key and $pad
 *
 * @param string $key The secret key
 * @param string $pad Is equal to $opad or $ipad
 *
 * @return string
 */
function _xor($key, $pad) {
    global $ascii, $opad, $ipad;
    if (in_array($pad, [$opad, $ipad])) {
        return strtr($key, $ascii, $pad);
    }
}


/**
 * Class KHMAC.
 *
 * This class allows you to the generation of a MAC (Message Authentication
 * Code) from a cryptographic hash function.
 */
class KHMAC
{
    /**
     * @var HashContext
     */
    private $_inner;
    /**
     * @var HashContext
     */
    private $_outer;
    /**
     * @var string A hash name
     */
    private $_hashname;


    /**
     * Create a new KHMAC object.
     *
     * @param string $key The secret key. This must be kept secret
     * @param string $msg The data where HMAC is calculated
     * @param string $hashname A hash function name
     */
    public function __construct($key = "", $msg = "", $hashname = "sha1") {
        global $opad, $ipad;
        $this->_hashname = $hashname;

        // Test if the key is a string
        if (!is_string($key)) {
            throw new Exception("This key is invalid !");
        }

        // Test if the message is a string
        if (!is_string($msg)) {
            throw new Exception("This message is not a string !");
        }

        // Test if the hash function is supported
        if (!array_key_exists($hashname, BLOCK_SIZES)) {
            throw new Exception("Unsupported hash type !");
        }

        $this->_outer = hash_init($hashname);
        $this->_inner = hash_init($hashname);

        // Determine the key

        # block sizes of the hash algorithm
        $block_size = BLOCK_SIZES[$hashname];

        if ($block_size < strlen($key)) {
            $key = hash($hashname, $key, true);
        }
        # the key length is equal to the block size
        $key = str_pad($key, $block_size, "\0");

        // Calculate the HMAC
        hash_update($this->_outer, _xor($key, $opad));
        hash_update($this->_inner, _xor($key, $ipad));

    }
}


?>
