# Keyed-Hash Message Authentication Code, PHP implementation

This extension is an implementation of the HMAC algorithm described by the standard [Key hash message authentication code (HMAC) (FIPS PUB 198).](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf).

**This implementation is written in PHP 7.4**

## Install
```sh
$ git clone https://github.com/mahtat555/PHPhmac.git
```

## Usage
```php
<?php
include "PHPhmac/khmac.php";

/**
 * Example 1
 */
$msg1 = "I am Mr. Yassin !";
$hmac1 = new KHMAC("my secret key", $msg1, "sha1");
// Test the `hexdigest()` method
echo $hmac1->hexdigest() . "\n";
// Test the `digest()` method
echo $hmac1->digest() . "\n";


/**
 * Example 2
 */
$msg2 = "I am Mr. ";
$hmac2 = new KHMAC("my secret key", $msg2, "sha1");
// Test the `verify()` method
# Test the equality of $hmac1 and $hmac2
if ($hmac1->verify($hmac2)) {
    echo "True\n";
} else {
    echo "False\n";
}


/**
 * Example 3
 */
// Test the `update()` method
$hmac2->update("Yassin !");
# Test the equality of $hmac1 and $hmac2
if ($hmac1->verify($hmac2)) {
    echo "True\n";
} else {
    echo "False\n";
}


/**
 * Example 4
 */
// Test the `hashname()` method
echo '$hash1 function name : ' . $hmac1->hashname() . "\n";
echo '$hash2 function name : ' . $hmac2->hashname() . "\n";


/**
 * Example 5
 */
// Test the `copy()` method
$hmac3 = $hmac1->copy();
$hmac3->update(" I am 25 years old.");
# Test the equality of $hmac1 and $hmac3
if ($hmac3->verify($hmac1)) {
    echo "True\n";
} else {
    echo "False\n";
}

/**
 * Example 6
 */
// Test the `khmac()` function
$hmac4 = khmac(
    "my secret key",
    "I am Mr. Yassin ! I am 25 years old.",
    "sha256"
);
# Test the equality of $hmac3 and $hmac4
if ($hmac3->verify($hmac4)) {
    echo "True\n";
} else {
    echo "False\n";
}
?>
```
