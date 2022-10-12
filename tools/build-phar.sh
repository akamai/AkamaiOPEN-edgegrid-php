#!/bin/bash
export PATH=vendor/bin:$PATH
if [[ -z $1 ]]
then
    export VERSION=""
else
	export VERSION="-$1"
fi

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd $DIR && cd ../
if [[ ! -d "build/phar" ]]
then
    mkdir -p build/phar
fi

# Create the bootstrap file if necessary
echo "<?php
/* Generate the stub that will load the autoloader */
if (!file_exists('./build/phar')) {
    mkdir('./build/phar', 0775, true);
}

\$stub = <<<EOF
<?php
if (class_exists('Phar')) {
   Phar::mapPhar('akamai-open-edgegrid-auth.phar');
}

Phar::interceptFileFuncs();
require_once 'phar://' .__FILE__. '/vendor/autoload.php';
__HALT_COMPILER(); ?>
EOF;

file_put_contents('build/phar/stub.php', \$stub);" > build/phar/bootstrap.php

php build/phar/bootstrap.php

if [[ -f $HOME/.composer/vendor/bin/box ]]
then
    composer install --no-dev -o -q
    php -dphar.readonly=0 $HOME/.composer/vendor/bin/box compile
    composer install -q
else
    composer install -o -q
    php -dphar.readonly=0 ./vendor/bin/box compile
    composer install -q
fi

mv akamai-open-edgegrid-auth.phar "akamai-open-edgegrid-auth${VERSION}.phar"

echo "<?php
include 'akamai-open-edgegrid-auth${VERSION}.phar';
\$auth = \Akamai\Open\EdgeGrid\Authentication::createFromEdgeRcFile('default', './tests/edgerc/.edgerc');
var_dump(\$auth);" > test.php
echo "Running test.php";
php test.php
rm test.php
