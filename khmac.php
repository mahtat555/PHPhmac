<?php
/**
 * This module is part of the project PHPhmac.
 *
 * This module is an PHP implementation of the HMAC algorithm described by the
 * standard <<Key hash message authentication code (HMAC) (FIPS PUB 198)>>.
 */


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


?>
