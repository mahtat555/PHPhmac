<?php
/**
 * This module is part of the project PHPhmac.
 */

include "khmac.php";

// Example 1
$msg1 = "I am Mr. Yassin !";
$msg2 = "I am Mr. ";
$hmac1 = new KHMAC("my secret key", $msg1, "sha1");
$hmac2 = new KHMAC("my secret key", $msg2, "sha1");
# Test the equality of $hmac1 and $hmac2
if ($hmac1->verify($hmac2)) {
    echo "True\n";
} else {
    echo "False\n";
}


// Example 2
$hmac2->update("Yassin !");
# Test the equality of $hmac1 and $hmac2
if ($hmac1->verify($hmac2)) {
    echo "True\n";
} else {
    echo "False\n";
}

?>
