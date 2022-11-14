#!/bin/bash
set -eo pipefail
export PATH=vendor/bin:$PATH
if [[ -z $1 ]]
then
  export VERSION=""
else
	export VERSION="-$1"
fi

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd $DIR && cd ../

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

echo "Running test.php";
php ./build/test.php
