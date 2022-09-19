<?php

/**
 * Akamai {OPEN} EdgeGrid Auth for PHP
 *
 * @author Davey Shafik <dshafik@akamai.com>
 * @copyright Copyright 2016 Akamai Technologies, Inc. All rights reserved.
 * @license Apache 2.0
 * @link https://github.com/akamai-open/AkamaiOPEN-edgegrid-php
 * @link https://developer.akamai.com
 * @link https://developer.akamai.com/introduction/Client_Auth.html
 */

namespace Akamai\Open\EdgeGrid\Tests\Client;

class AuthenticationTest extends \PHPUnit\Framework\TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->prophet = new \Prophecy\Prophet();
    }

    protected function tearDown(): void
    {
        $this->prophet->checkPredictions();
        parent::tearDown();
    }

    /**
     * @dataProvider createAuthHeaderDataProvider
     */
    public function testCreateAuthHeader(
        $auth,
        $body,
        $expected,
        $headers,
        $headersToSign,
        $host,
        $maxBody,
        $method,
        $name,
        $nonce,
        $path,
        $query,
        $timestamp
    ) {
        $this->setName($name);

        $mockTimestamp = $this->prophet->prophesize('\Akamai\Open\EdgeGrid\Authentication\Timestamp');
        $mockTimestamp->__toString()->willReturn($timestamp);
        $mockTimestamp->isValid()->willReturn(true);
        $mockNonce = $this->prophet->prophesize('\Akamai\Open\EdgeGrid\Authentication\Nonce');
        $mockNonce->__toString()->willReturn($nonce);

        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setAuth($auth['client_token'], $auth['client_secret'], $auth['access_token']);
        $authentication->setHttpMethod($method);
        $authentication->setHeaders($headers);
        $authentication->setHeadersToSign($headersToSign);
        $authentication->setQuery($query);
        $authentication->setPath($path);
        $authentication->setHost($host);
        $authentication->setBody($body);
        $authentication->setMaxBodySize($maxBody);
        $authentication->setTimestamp($mockTimestamp->reveal());
        $authentication->setNonce($mockNonce->reveal());

        $result = $authentication->createAuthHeader();

        $this->assertEquals($expected, $result);
    }

    public function testCreateAuthHeaderTrailingSpaces()
    {
        $mockTimestamp = $this->prophet->prophesize('\Akamai\Open\EdgeGrid\Authentication\Timestamp');
        $mockTimestamp->__toString()->willReturn("20170831T19:34:21+0000");
        $mockTimestamp->isValid()->willReturn(true);
        $mockNonce = $this->prophet->prophesize('\Akamai\Open\EdgeGrid\Authentication\Nonce');
        $mockNonce->__toString()->willReturn("nonce-xx-xxxx-xxxx-xxxx-xxxxxxxxxxxx");

        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setHttpMethod("POST");
        $authentication->setPath("/ccu/v3/invalidate/url/production");
        $authentication->setHost("akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net");
        $authentication->setBody("{\"objects\":[\"https:\/\/example.org\/\",\"https:\/\/example.org\/test.html\"]}");
        $authentication->setTimestamp($mockTimestamp->reveal());
        $authentication->setNonce($mockNonce->reveal());

        $authentication->setAuth(
            'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
            'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
            'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
        );
        $authentication->setMaxBodySize("15");
        $noSpacesResult = $authentication->createAuthHeader();


        $authentication->setAuth(
            'akab-client-token-xxx-xxxxxxxxxxxxxxxx ',
            ' xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx= ',
            ' akab-access-token-xxx-xxxxxxxxxxxxxxxx'
        );
        $authentication->setMaxBodySize(" 15 ");
        $spacesResult = $authentication->createAuthHeader();

        $this->assertEquals($noSpacesResult, $spacesResult);
    }

    public function testDefaultTimestamp()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setAuth('test', 'test', 'test');
        $authentication->setHttpMethod('GET');
        $authentication->setPath('/test');
        $authentication->setHost('https://example.org');
        $authentication->createAuthHeader();

        $reflector = new \ReflectionClass($authentication);
        $reflectedAttr = $reflector->getProperty('timestamp');
        $reflectedAttr->setAccessible(true);

        $this->assertInstanceOf(
            '\Akamai\Open\EdgeGrid\Authentication\Timestamp',
            $reflectedAttr->getValue($authentication)
        );
    }

    public function testDefaultNonce()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setAuth('test', 'test', 'test');
        $authentication->setHttpMethod('GET');
        $authentication->setPath('/test');
        $authentication->setHost('https://example.org');
        $authentication->createAuthHeader();
        $authentication->setNonce();

        $reflector = new \ReflectionClass($authentication);
        $reflectedAttr = $reflector->getProperty('nonce');
        $reflectedAttr->setAccessible(true);

        $this->assertInstanceOf(
            '\Akamai\Open\EdgeGrid\Authentication\Nonce',
            $reflectedAttr->getValue($authentication)
        );
    }

    public function testTimestampTimeout()
    {
        $this->expectException(\Akamai\Open\EdgeGrid\Authentication\Exception\SignerException\InvalidSignDataException::class);
        $this->expectExceptionMessage('Timestamp is invalid. Too old?');

        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setAuth('test', 'test', 'test');
        $authentication->setHttpMethod('GET');
        $authentication->setPath('/test');
        $authentication->setHost('https://example.org');

        $timestamp = new \Akamai\Open\EdgeGrid\Authentication\Timestamp();
        $timestamp->setValidFor('PT0S');
        $authentication->setTimestamp($timestamp);
        sleep(1);
        $authentication->createAuthHeader();
    }

    public function testSignHeadersArray()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();

        $reflection = new \ReflectionMethod($authentication, 'canonicalizeHeaders');
        $reflection->setAccessible(true);

        $authentication->setAuth('test', 'test', 'test');
        $authentication->setHttpMethod('GET');
        $authentication->setPath('/test');
        $authentication->setHost('https://example.org');
        $authentication->setHeaders(array(
            'X-Test-1' => array('Value1', 'value2')
        ));
        $authentication->setHeadersToSign(array('X-Test-1'));

        $this->assertEquals('x-test-1:Value1', $reflection->invoke($authentication));

        $authentication->setHeaders(array(
            'X-Test-1' => array()
        ));
        $authentication->setHeadersToSign(array('X-Test-1'));
        $this->assertEmpty($reflection->invoke($authentication));
    }

    public function testGetSetHost()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setHost('example.org');
        $this->assertEquals(
            'example.org',
            $authentication->getHost()
        );

        $this->assertNull($authentication->getPath());
        $this->assertArrayNotHasKey('query', $authentication->getConfig());

        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setHost('http://example.com');
        $this->assertEquals(
            'example.com',
            $authentication->getHost()
        );

        $this->assertNull($authentication->getPath());
        $this->assertArrayNotHasKey('query', $authentication->getConfig());
    }

    public function testSetHostWithPath()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();

        $authentication->setHost('example.net/path');
        $this->assertEquals(
            'example.net',
            $authentication->getHost()
        );
        $this->assertEquals('/path', $authentication->getPath());
        $this->assertArrayNotHasKey('query', $authentication->getConfig());

        $authentication->setHost('http://example.org/newpath');
        $this->assertEquals(
            'example.org',
            $authentication->getHost()
        );
        $this->assertEquals('/newpath', $authentication->getPath());
        $this->assertArrayNotHasKey('query', $authentication->getConfig());
    }

    public function testSetHostWithQuery()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();

        $authentication->setHost('example.net/path?query=string');
        $this->assertEquals(
            'example.net',
            $authentication->getHost()
        );
        $this->assertEquals('/path', $authentication->getPath());
        $this->assertArrayHasKey('query', $authentication->getConfig());
        $this->assertEquals(
            'query=string',
            $authentication->getQuery()
        );

        $authentication->setHost('http://example.org/newpath?query=newstring');
        $this->assertEquals(
            'example.org',
            $authentication->getHost()
        );
        $this->assertEquals('/newpath', $authentication->getPath());
        $this->assertArrayHasKey('query', $authentication->getConfig());
        $this->assertEquals(
            'query=newstring',
            $authentication->getQuery()
        );

        $authentication->setHost('http://example.org?query=newstring');
        $this->assertEquals(
            'example.org',
            $authentication->getHost()
        );
        $this->assertEquals('/', $authentication->getPath());
        $this->assertArrayHasKey('query', $authentication->getConfig());
        $this->assertEquals(
            'query=newstring',
            $authentication->getQuery()
        );

        $authentication->setHost('http://example.net/?query=string');
        $this->assertEquals(
            'example.net',
            $authentication->getHost()
        );
        $this->assertEquals('/', $authentication->getPath());
        $this->assertArrayHasKey('query', $authentication->getConfig());
        $this->assertEquals(
            'query=string',
            $authentication->getQuery()
        );
    }

    public function testGetSetPath()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();

        $authentication->setPath('/path');
        $this->assertEmpty(
            $authentication->getHost()
        );
        $this->assertEquals('/path', $authentication->getPath());
        $this->assertArrayNotHasKey('query', $authentication->getConfig());
        $this->assertEmpty($authentication->getQuery());

        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setPath('https://example.net/path');
        $this->assertEquals(
            'example.net',
            $authentication->getHost()
        );
        $this->assertEquals('/path', $authentication->getPath());
        $this->assertArrayNotHasKey('query', $authentication->getConfig());
        $this->assertEmpty($authentication->getQuery());

        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setPath('/newpath?query=string');
        $this->assertEmpty(
            $authentication->getHost()
        );
        $this->assertEquals('/newpath', $authentication->getPath());
        $this->assertArrayHasKey('query', $authentication->getConfig());
        $this->assertEquals(
            'query=string',
            $authentication->getQuery()
        );
        $this->assertEquals('query=string', $authentication->getQuery());

        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setPath('https://example.net/path?query=newstring');
        $this->assertEquals(
            'example.net',
            $authentication->getHost()
        );
        $this->assertEquals('/path', $authentication->getPath());
        $this->assertArrayHasKey('query', $authentication->getConfig());
        $this->assertEquals(
            'query=newstring',
            $authentication->getQuery()
        );
        $this->assertEquals('query=newstring', $authentication->getQuery());
    }

    /**
     * @dataProvider createFromEdgeRcProvider
     */
    public function testCreateFromEdgeRcDefault($section, $file)
    {
        $_SERVER['HOME'] = __DIR__ . '/edgerc';
        $authentication = \Akamai\Open\EdgeGrid\Authentication::createFromEdgeRcFile($section, $file);

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    public function testCreateFromEdgeRcUseCwd()
    {
        $this->expectException(\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException::class);
        $this->expectExceptionMessage('Section "default" does not exist!');

        $_SERVER['HOME'] = '/non-existant';
        $unlink = false;
        if (!file_exists('./.edgerc')) {
            touch('./.edgerc');
            $unlink = true;
        }

        try {
            $auth = \Akamai\Open\EdgeGrid\Authentication::createFromEdgeRcFile();
            $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $auth);
        } catch (\Exception $e) {
            if ($unlink) {
                unlink('./.edgerc');
            }
            throw $e;
        }

        if ($unlink) {
            unlink('./.edgerc');
        }
    }

    public function testCreateFromEdgeRcNonExistant()
    {
        $this->expectException(\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException::class);
        $this->expectExceptionMessage('Path to .edgerc file "/non-existant/.edgerc" does not exist!');

        $auth = \Akamai\Open\EdgeGrid\Authentication::createFromEdgeRcFile(null, '/non-existant/.edgerc');
    }

    /**
     * @requires OS ^(?!.*WIN).*$
     */
    public function testCreateFromEdgeRcNonReadable()
    {
        $this->expectException(\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException::class);
        $this->expectExceptionMessage('Unable to read .edgerc file!');

        $filename = tempnam(sys_get_temp_dir(), '.');
        touch(tempnam(sys_get_temp_dir(), '.'));
        chmod($filename, 0000);

        try {
            $auth = \Akamai\Open\EdgeGrid\Authentication::createFromEdgeRcFile(null, $filename);
        } catch (\Exception $e) {
            chmod($filename, 0777);
            unlink($filename);
            throw $e;
        }

        chmod($filename, 0777);
        unlink($filename);
    }

    public function testCreateFromEdgeRcColons()
    {
        $file = __DIR__ . '/edgerc/.edgerc.invalid';
        $authentication = \Akamai\Open\EdgeGrid\Authentication::createFromEdgeRcFile(null, $file);

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    public function testCreateFromEdgeRcColonsWithSpaces()
    {
        $file = __DIR__ . '/edgerc/.edgerc.invalid-spaces';
        $authentication = \Akamai\Open\EdgeGrid\Authentication::createFromEdgeRcFile(null, $file);

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateFromEnvNoSection()
    {
        $_ENV['AKAMAI_HOST'] = 'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net';
        $_ENV['AKAMAI_CLIENT_TOKEN'] = 'akab-client-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_CLIENT_SECRET'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=';
        $_ENV['AKAMAI_ACCESS_TOKEN'] = 'akab-access-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_MAX_SIZE'] = 2048;

        $authentication = \Akamai\Open\EdgeGrid\Authentication::createFromEnv();

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateFromEnvDefaultSection()
    {
        $_ENV['AKAMAI_DEFAULT_HOST'] = 'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net';
        $_ENV['AKAMAI_DEFAULT_CLIENT_TOKEN'] = 'akab-client-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_DEFAULT_CLIENT_SECRET'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=';
        $_ENV['AKAMAI_DEFAULT_ACCESS_TOKEN'] = 'akab-access-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_DEFAULT_MAX_SIZE'] = 2048;

        $authentication = \Akamai\Open\EdgeGrid\Authentication::createFromEnv();

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateFromEnvPreferSection()
    {
        $_ENV['AKAMAI_HOST'] = false;
        $_ENV['AKAMAI_CLIENT_TOKEN'] = false;
        $_ENV['AKAMAI_CLIENT_SECRET'] = false;
        $_ENV['AKAMAI_ACCESS_TOKEN'] = false;
        $_ENV['AKAMAI_MAX_SIZE'] = 0;

        $_ENV['AKAMAI_TESTING_HOST'] = 'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net';
        $_ENV['AKAMAI_TESTING_CLIENT_TOKEN'] = 'akab-client-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_TESTING_CLIENT_SECRET'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=';
        $_ENV['AKAMAI_TESTING_ACCESS_TOKEN'] = 'akab-access-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_TESTING_MAX_SIZE'] = 2048;

        $authentication = \Akamai\Open\EdgeGrid\Authentication::createFromEnv('testing');

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateFromEnvNoMaxSize()
    {
        $_ENV['AKAMAI_HOST'] = 'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net';
        $_ENV['AKAMAI_CLIENT_TOKEN'] = 'akab-client-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_CLIENT_SECRET'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=';
        $_ENV['AKAMAI_ACCESS_TOKEN'] = 'akab-access-token-xxx-xxxxxxxxxxxxxxxx';

        $authentication = \Akamai\Open\EdgeGrid\Authentication::createFromEnv();

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(131072, $reflectedMaxBodySize->getValue($authentication));
    }

    public function testCreateFromEnvInvalid()
    {
        $this->expectException(\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException::class);
        $this->expectExceptionMessage('Environment variables AKAMAI_HOST or AKAMAI_DEFAULT_HOST do not exist');

        $authentication = \Akamai\Open\EdgeGrid\Authentication::createFromEnv();
    }

    public function testCreateFromEnvInvalidSection()
    {
        $this->expectException(\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException::class);
        $this->expectExceptionMessage('Environment variable AKAMAI_TESTING_HOST does not exist');

        $authentication = \Akamai\Open\EdgeGrid\Authentication::createFromEnv('testing');
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateInstancePreferEnv()
    {
        $_ENV['AKAMAI_HOST'] = 'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net';
        $_ENV['AKAMAI_CLIENT_TOKEN'] = 'akab-client-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_CLIENT_SECRET'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=';
        $_ENV['AKAMAI_ACCESS_TOKEN'] = 'akab-access-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_MAX_SIZE'] = 2048;

        $authentication = \Akamai\Open\EdgeGrid\Authentication::createInstance(
            'default',
            __DIR__ . '/edgerc/.edgerc.default-testing'
        );

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    public function testCreateInstanceFallbackEdgeRc()
    {
        $authentication = \Akamai\Open\EdgeGrid\Authentication::createInstance('default', __DIR__ . '/edgerc/.edgerc');

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateInstanceSection()
    {
        $_ENV['AKAMAI_TESTING_HOST'] = 'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net';
        $_ENV['AKAMAI_TESTING_CLIENT_TOKEN'] = 'akab-client-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_TESTING_CLIENT_SECRET'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=';
        $_ENV['AKAMAI_TESTING_ACCESS_TOKEN'] = 'akab-access-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_TESTING_MAX_SIZE'] = 2048;

        $authentication = \Akamai\Open\EdgeGrid\Authentication::createInstance('testing', __DIR__ . '/edgerc/.edgerc');

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateInstanceSectionFallback()
    {
        $_ENV['AKAMAI_HOST'] = false;
        $_ENV['AKAMAI_CLIENT_TOKEN'] = false;
        $_ENV['AKAMAI_CLIENT_SECRET'] = false;
        $_ENV['AKAMAI_ACCESS_TOKEN'] = false;
        $_ENV['AKAMAI_MAX_SIZE'] = 0;

        $authentication = \Akamai\Open\EdgeGrid\Authentication::createInstance(
            'testing',
            __DIR__ . '/edgerc/.edgerc.testing'
        );

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateInstanceSectionFallbackEnv()
    {
        $_ENV['AKAMAI_HOST'] = 'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net';
        $_ENV['AKAMAI_CLIENT_TOKEN'] = 'akab-client-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_CLIENT_SECRET'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=';
        $_ENV['AKAMAI_ACCESS_TOKEN'] = 'akab-access-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_MAX_SIZE'] = 2048;

        $authentication = \Akamai\Open\EdgeGrid\Authentication::createInstance('testing', __DIR__ . '/edgerc/.edgerc');

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateInstanceSectionFallbackInvalidEdgerc()
    {
        $_ENV['AKAMAI_HOST'] = 'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net';
        $_ENV['AKAMAI_CLIENT_TOKEN'] = 'akab-client-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_CLIENT_SECRET'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=';
        $_ENV['AKAMAI_ACCESS_TOKEN'] = 'akab-access-token-xxx-xxxxxxxxxxxxxxxx';
        $_ENV['AKAMAI_MAX_SIZE'] = 2048;

        $authentication = \Akamai\Open\EdgeGrid\Authentication::createInstance(
            'testing',
            __DIR__ . '/edgerc/.edgerc.invalid'
        );

        $reflector = new \ReflectionClass($authentication);
        $reflectedAuth = $reflector->getProperty('auth');
        $reflectedMaxBodySize = $reflector->getProperty('max_body_size');
        $reflectedAuth->setAccessible(true);
        $reflectedMaxBodySize->setAccessible(true);

        $this->assertInstanceOf('\Akamai\Open\EdgeGrid\Authentication', $authentication);
        $this->assertEquals(
            array(
                'client_token' => 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                'client_secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                'access_token' => 'akab-access-token-xxx-xxxxxxxxxxxxxxxx'
            ),
            $reflectedAuth->getValue($authentication)
        );
        $this->assertEquals(
            'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net',
            $authentication->getHost()
        );
        $this->assertEquals(2048, $reflectedMaxBodySize->getValue($authentication));
    }

    public function testCreateInstanceSectionFallbackInvalidEdgercNoEnv()
    {
        $this->expectException(\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException::class);
        $this->expectExceptionMessage('Unable to create instance using environment or .edgerc file');

        try {
            $authentication = \Akamai\Open\EdgeGrid\Authentication::createInstance(
                'testing',
                __DIR__ . '/edgerc/.edgerc.invalid'
            );
        } catch (\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException $e) {
            $this->assertInstanceOf(
                '\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException',
                $e->getPrevious()
            );

            $this->assertEquals('Section "testing" does not exist!', $e->getPrevious()->getMessage());

            throw $e;
        }
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateInstanceInvalidEdgercInvalidEnv()
    {
        $this->expectException(\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException::class);
        $this->expectExceptionMessage('Unable to create instance using environment or .edgerc file');

        $_ENV['AKAMAI_HOST'] = 'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net';

        try {
            $authentication = \Akamai\Open\EdgeGrid\Authentication::createInstance(
                "default",
                __DIR__ . '/edgerc/.edgerc.testing'
            );
        } catch (\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException $e) {
            $this->assertInstanceOf(
                '\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException',
                $e->getPrevious()
            );

            $this->assertEquals('Section "default" does not exist!', $e->getPrevious()->getMessage());

            throw $e;
        }
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateInstanceInvalidEdgercInvalidEnvSection()
    {
        $this->expectException(\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException::class);
        $this->expectExceptionMessage('Unable to create instance using environment or .edgerc file');
        $_ENV['AKAMAI_TESTING_HOST'] = 'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net';

        try {
            $authentication = \Akamai\Open\EdgeGrid\Authentication::createInstance(
                "testing",
                __DIR__ . '/edgerc/.edgerc'
            );
        } catch (\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException $e) {
            $this->assertInstanceOf(
                '\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException',
                $e->getPrevious()
            );

            $this->assertEquals(
                'Section "testing" does not exist!',
                $e->getPrevious()->getMessage()
            );

            throw $e;
        }
    }

    /**
     * @backupGlobals enabled
     */
    public function testCreateInstanceInvalidEdgercInvalidEnvSectionInvalidDefaultEnv()
    {
        $this->expectException(\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException::class);
        $this->expectExceptionMessage('Unable to create instance using environment or .edgerc file');

        $_ENV['AKAMAI_HOST'] = 'akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net';

        try {
            $authentication = \Akamai\Open\EdgeGrid\Authentication::createInstance(
                "testing",
                __DIR__ . '/edgerc/.edgerc'
            );
        } catch (\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException $e) {
            $this->assertInstanceOf(
                '\Akamai\Open\EdgeGrid\Authentication\Exception\ConfigException',
                $e->getPrevious()
            );

            $this->assertEquals(
                'Environment variables AKAMAI_CLIENT_TOKEN or AKAMAI_DEFAULT_CLIENT_TOKEN do not exist',
                $e->getPrevious()->getMessage()
            );

            throw $e;
        }
    }

    public function testSetConfig()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();

        $config = array('test' => 'value');
        $authentication->setConfig($config);

        $this->assertEquals($config, $authentication->getConfig());

        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setQuery('query=string');
        $authentication->setConfig($config);

        $config['query'] = 'query=string';
        $this->assertEquals($config, $authentication->getConfig());
    }

    public function testGetSetQuery()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setQuery('query=string');
        $this->assertEquals('query=string', $authentication->getQuery());

        $authentication->setQuery(array('query' => 'string'));
        $this->assertEquals(array('query' => 'string'), $authentication->getQuery());
    }

    public function testSetQueryEncoding()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setQuery('query=string%20with%20spaces');
        $this->assertEquals('query=string%20with%20spaces', $authentication->getQuery());

        $authentication->setQuery('query=string+with+spaces');
        $this->assertEquals('query=string%20with%20spaces', $authentication->getQuery());
    }

    public function testGetSetHttpMethod()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setHttpMethod('GET');
        $this->assertEquals('GET', $authentication->getHttpMethod());

        $authentication->setHttpMethod('get');
        $this->assertEquals('GET', $authentication->getHttpMethod());

        $authentication->setHttpMethod('POST');
        $this->assertEquals('POST', $authentication->getHttpMethod());
    }

    public function testGetSetConfig()
    {
        $config = array('test' => 'value');

        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setConfig($config);
        $this->assertEquals($config, $authentication->getConfig());
    }

    public function testGetSetConfigMerge()
    {
        $config = array('test' => 'value');

        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setConfig($config);
        $authentication->setConfig(array('test2' => 'value2'));
        $this->assertEquals(array(
            'test' => 'value',
            'test2' => 'value2'
        ), $authentication->getConfig());
    }

    public function testGetSetBody()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setBody('testing');
        $this->assertEquals('testing', $authentication->getBody());
    }

    public function testGetSetBodyTruncate()
    {
        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setMaxBodySize(4);
        $authentication->setBody('testing');
        $this->assertEquals('test', $authentication->getBody(true));
    }

    public function testGetSetHeaders()
    {
        $headers = array(
            'X-Test-Header' => 'value'
        );

        $authentication = new \Akamai\Open\EdgeGrid\Authentication();
        $authentication->setHeaders($headers);
        $this->assertEquals($headers, $authentication->getHeaders());
    }

    public function createFromEdgeRcProvider()
    {
        return array(
            array(
                'section' => null,
                'file' => null,
            ),
            array(
                'section' => 'default',
                'file' => null,
            ),
            array(
                'section' => 'testing',
                'file' => __DIR__ . '/edgerc/.edgerc.testing',
            ),
            array(
                'section' => 'testing',
                'file' => __DIR__ . '/edgerc/.edgerc.default-testing',
            )
        );
    }

    public function createAuthHeaderDataProvider()
    {
        $testdata = json_decode(file_get_contents(__DIR__ . '/testdata.json'), true);

        $defaults = array(
            'auth' => array(
                'client_token' => $testdata['client_token'],
                'client_secret' => $testdata['client_secret'],
                'access_token' => $testdata['access_token'],
            ),
            'host' => parse_url($testdata['base_url'], PHP_URL_HOST),
            'headersToSign' => $testdata['headers_to_sign'],
            'nonce' => $testdata['nonce'],
            'timestamp' => $testdata['timestamp'],
            'maxBody' => $testdata['max_body'],
        );

        foreach ($testdata['tests'] as &$test) {
            $data = array_merge($defaults, array(
                'method' => $test['request']['method'],
                'path' => $test['request']['path'],
                'expected' => $test['expectedAuthorization'],
                'query' => isset($test['request']['query']) ? $test['request']['query'] : null,
                'body' => isset($test['request']['data']) ? $test['request']['data'] : null,
                'name' => $test['testName'],
            ));

            $data['headers'] = array();
            if (isset($test['request']['headers'])) {
                array_walk_recursive($test['request']['headers'], function ($value, $key) use (&$data) {
                    $data['headers'][$key] = $value;
                });
            }

            ksort($data);

            $test = $data;
        }

        return $testdata['tests'];
    }
}
