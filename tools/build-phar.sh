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

if [[ -n $VERSION ]]
then
  mv akamai-open-edgegrid-auth.phar "akamai-open-edgegrid-auth${VERSION}.phar"
fi

echo "Running smoke test";
php ./build/test.php
