<?php
/**
 * This module is part of the project PHPhmac.
 */

include "khmac.php";

/**
 * Example 1
 */
$msg1 = "I am Mr. Yassin !";
$hmac1 = new KHMAC("my secret key", $msg1, "sha1");
// Test the hexdigest() method
echo $hmac1->hexdigest() . "\n";
// Test the digest() method
echo $hmac1->digest() . "\n";


/**
 * Example 2
 */
$msg2 = "I am Mr. ";
$hmac2 = new KHMAC("my secret key", $msg2, "sha1");
// Test the verify() method
# Test the equality of $hmac1 and $hmac2
if ($hmac1->verify($hmac2)) {
    echo "True\n";
} else {
    echo "False\n";
}


/**
 * Example 3
 */
// Test the update() method
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
// Test the hashname() method
echo '$hash1 function name : ' . $hmac1->hashname() . "\n";
echo '$hash2 function name : ' . $hmac2->hashname() . "\n";


/**
 * Example 5
 */
// Test the copy() method
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
// Test the khmac() function
$hmac4 = khmac(
    "my secret key",
    "I am Mr. Yassin ! I am 25 years old."
);
# Test the equality of $hmac3 and $hmac4
if ($hmac3->verify($hmac4)) {
    echo "True\n";
} else {
    echo "False\n";
}

?>
