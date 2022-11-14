<?php
if (class_exists('Phar')) {
   Phar::mapPhar('akamai-open-edgegrid-auth.phar');
}

Phar::interceptFileFuncs();
require_once 'phar://' .__FILE__. '/vendor/autoload.php';
__HALT_COMPILER(); ?>