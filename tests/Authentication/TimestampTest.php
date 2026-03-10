<?php
namespace Akamai\Open\EdgeGrid\Tests\Client\Authentication;

class TimestampTest extends \PHPUnit\Framework\TestCase
{
    public function testTimestampFormat()
    {
        $timestamp = new \Akamai\Open\EdgeGrid\Authentication\Timestamp();

        $check = \DateTime::createFromFormat('Ymd\TH:i:sO', (string) $timestamp, new \DateTimeZone('UTC'));
        $this->assertEquals(
            $check->format(\Akamai\Open\EdgeGrid\Authentication\Timestamp::FORMAT),
            (string) $timestamp
        );
    }


    public function testIsValid()
    {
        $timestamp = new \Akamai\Open\EdgeGrid\Authentication\Timestamp();
        $this->assertTrue($timestamp->isValid());
        $timestamp->setValidFor('PT0S');
        sleep(1);
        $this->assertFalse($timestamp->isValid());
    }
}
