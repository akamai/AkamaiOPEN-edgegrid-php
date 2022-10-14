# akamai-open/edgegrid-auth

[Akamai EdgeGrid Authentication](https://techdocs.akamai.com/developer/docs/set-up-authentication-credentials) for PHP

This library requires PHP 8+ and implements the Akamai EdgeGrid Authentication scheme for PHP.

## Install

To install, use [`composer`](http://getcomposer.org):

```sh
$ composer require akamai-open/edgegrid-auth
```

### Alternative installation methods

#### Single file (PHAR)

Download the PHAR file from the [releases](https://github.com/akamai/AkamaiOPEN-edgegrid-php/releases) page and include it inside your code:

    ```php
    include 'akamai-open-edgegrid-auth.phar';

    // Library is ready to use
    ```

#### Clone or download

1. Either clone or download to pull down a copy of this repository.

    * Clone the repository using [git](https://github.com/akamai/AkamaiOPEN-edgegrid-php.git) or [subversion](https://github.com/akamai/AkamaiOPEN-edgegrid-php).
    * Download the latest [ZIP archive](https://github.com/akamai/AkamaiOPEN-edgegrid-php/archive/master.zip) or [specific release ZIP archive](https://github.com/akamai/AkamaiOPEN-edgegrid-php/releases).

1. Use the composer autoloader and install the dependencies.

    ```bash
      $ composer install
    ```

1. Include the autoloader.

    ```php
    require_once 'vendor/autoload.php';
    ```

    If you don't use the autoloader, include all the required classes manually in your code.

    ```php
    require_once 'src/Authentication.php';
    require_once 'src/Authentication/Timestamp.php';
    require_once 'src/Authentication/Nonce.php';
    require_once 'src/Authentication/Exception.php';
    require_once 'src/Authentication/Exception/ConfigException.php';
    require_once 'src/Authentication/Exception/SignerException.php';
    require_once 'src/Authentication/Exception/SignerException/InvalidSignDataException.php';
    ```

## Use

Once you have installed the library, you can create the header value by calling the appropriate `\Akamai\Open\Edgegrid\Authentication::set*()` methods.

For example, using it with the built-in streams HTTP client might look like the following:

```php
$auth = \Akamai\Open\EdgeGrid\Authentication::createFromEdgeRcFile('default', '/.edgerc');
$auth->setHttpMethod('GET');
$auth->setPath('/identity-management/v3/user-profile');

$context = array(
  'http' => array(
    'header' => array(
      'Authorization: ' . $auth->createAuthHeader(),
      'Content-Type: application/json'
    )
  )
);

$context = stream_context_create($context);

$response = json_decode(file_get_contents('https://' . $auth->getHost() . $auth->getPath(), null, $context));
```

## License

Copyright © 2022 Akamai Technologies, Inc. All rights reserved

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
