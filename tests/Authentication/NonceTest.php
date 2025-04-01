<?php
namespace Akamai\Open\EdgeGrid\Tests\Client\Authentication;

class NonceTest extends \PHPUnit\Framework\TestCase
{
    public function testMakeNonce()
    {
        $nonce = new \Akamai\Open\EdgeGrid\Authentication\Nonce();

        $nonces = array();
        for ($i = 0; $i < 100; $i++) {
            $nonces[] = (string) $nonce;
        }

        $this->assertEquals(100, count(array_unique($nonces)));
    }

    public function testMakeNonceRandomBytes()
    {
        if (!function_exists('random_bytes')) {
            include __DIR__ . '/../random_bytes.php';
        }

        $nonce = new \Akamai\Open\EdgeGrid\Authentication\Nonce();

        $reflector = new \ReflectionClass($nonce);
        $reflectedFunction = $reflector->getProperty('function');
        $reflectedFunction->setAccessible(true);

        $this->assertEquals('random_bytes', $reflectedFunction->getValue($nonce));
    }
}
