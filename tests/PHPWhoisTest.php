<?php

namespace PHPWhois\Tests;

use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
class PHPWhoisTest extends TestCase
{
    public function testLookupDomain(): void
    {
        $whois = new \Whois();
        $result = $whois->Lookup('example.com');

        $this->assertIsArray($result['rawdata']);
        $this->assertIsArray($result['regrinfo']);
        $this->assertIsArray($result['regyinfo']);
        //print_r($result);
    }

    public function testLookupDomainFail(): void
    {
        $whois = new \Whois();
        $result = $whois->Lookup('fake-domain.fake-tld');

        $this->assertIsArray($result['rawdata']);
        $this->assertIsArray($result['regrinfo']);
        $this->assertArrayNotHasKey('regyinfo', $result);
        //print_r($result);
    }

    public function testLookupIp(): void
    {
        $whois = new \Whois();
        $result = $whois->Lookup('62.97.102.115');

        $this->assertIsArray($result['rawdata']);
        $this->assertIsArray($result['regrinfo']);
        $this->assertArrayNotHasKey('regyinfo', $result);
        //print_r($result);
    }

    public function testLookupAs(): void
    {
        $whois = new \Whois();
        $result = $whois->Lookup('AS220');

        $this->assertIsArray($result['rawdata']);
        $this->assertIsArray($result['regrinfo']);
        $this->assertArrayNotHasKey('regyinfo', $result);
        //print_r($result);
    }

    public function testLookupUseServer(): void
    {
        $whois = new \Whois();
        $whois->UseServer('ru', 'whois.apnic.net');
        $result = $whois->Lookup('yandex.ru');

        $this->assertIsArray($result['rawdata']);
        $this->assertIsArray($result['regrinfo']);
        $this->assertIsArray($result['regyinfo']);
        //print_r($result);
    }
}
