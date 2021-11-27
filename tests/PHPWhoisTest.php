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

        self::assertIsArray($result['rawdata']);
        self::assertIsArray($result['regrinfo']);
        self::assertIsArray($result['regyinfo']);
        //print_r($result);
    }

    public function testLookupDomainFail(): void
    {
        $whois = new \Whois();
        $result = $whois->Lookup('fake-domain.fake-tld');

        self::assertIsArray($result['rawdata']);
        self::assertIsArray($result['regrinfo']);
        self::assertArrayNotHasKey('regyinfo', $result);
        //print_r($result);
    }

    public function testLookupIp(): void
    {
        $whois = new \Whois();
        $result = $whois->Lookup('62.97.102.115');

        //print_r($result);
        self::assertIsArray($result['rawdata']);
        self::assertIsArray($result['regrinfo']);
        self::assertIsArray($result['regyinfo']);
    }

    public function testLookupAs(): void
    {
        $whois = new \Whois();
        $result = $whois->Lookup('AS220');

        self::assertIsArray($result['rawdata']);
        self::assertIsArray($result['regrinfo']);
        self::assertIsArray($result['regyinfo']);
        //print_r($result);
    }

    public function testLookupUseServer(): void
    {
        $whois = new \Whois();
        $whois->UseServer('ru', 'whois.apnic.net');
        $result = $whois->Lookup('yandex.ru');

        //print_r($result);
        self::assertIsArray($result['rawdata']);
        self::assertIsArray($result['regrinfo']);
        self::assertIsArray($result['regyinfo']);
    }

    public function dataProviderGetBlocks(): \Generator
    {
        yield [
            [
                '',
                '#',
                '',
            ],
            [],
        ];

        yield [
            \explode("\n", '% The WHOIS service offered by EURid and the access to the records
    % in the EURid WHOIS database are provided for information purposes
    % only. It allows persons to check whether a specific domain name
    % is still available or not and to obtain information related to
    % the registration records of existing domain names.
%
% EURid cannot, under any circumstances, be held liable in case the
    % stored information would prove to be wrong, incomplete or not
    % accurate in any sense.
%
% By submitting a query you agree not to use the information made
    % available to:
%
% - allow, enable or otherwise support the transmission of unsolicited,
%   commercial advertising or other solicitations whether via email or
%   otherwise;
% - target advertising in any possible way;
%
% - to cause nuisance in any possible way to the registrants by sending
    %   (whether by automated, electronic processes capable of enabling
    %   high volumes or other possible means) messages to them.
%
% Without prejudice to the above, it is explicitly forbidden to extract,
% copy and/or use or re-utilise in any form and by any means
    % (electronically or not) the whole or a quantitatively or qualitatively
    % substantial part of the contents of the WHOIS database without prior
    % and explicit permission by EURid, nor in any attempt hereof, to apply
    % automated, electronic processes to EURid (or its systems).
%
% You agree that any reproduction and/or transmission of data for
% commercial purposes will always be considered as the extraction of a
    % substantial part of the content of the WHOIS database.
%
% By submitting the query you agree to abide by this policy and accept
    % that EURid can take measures to limit the use of its WHOIS services
    % in order to protect the privacy of its registrants or the integrity
    % of the database.
%
% The EURid WHOIS service on port 43 (textual whois) never
    % discloses any information concerning the registrant.
% Registrant and on-site contact information can be obtained through use of the
    % webbased WHOIS service available from the EURid website www.eurid.eu
    %
% WHOIS example.eu
Domain: example.eu
Script: LATIN

Registrant:
        NOT DISCLOSED!
    Visit www.eurid.eu for webbased WHOIS.

    Technical:
        Organisation: INTERNET CZ, a.s.
    Language: cs
        Email: domain@forpsi.com

Registrar:
        Name: INTERNET CZ, a.s.
    Website: www.forpsi.com/

    Name servers:
        ns.forpsi.it
        ns.forpsi.cz
        ns.forpsi.net

Keys:
        flags:KSK protocol:3 algorithm:RSA_SHA512 pubKey:AwEAAcEdJN9mDWVoP+2lXwdUl0HMkErlLWQSiStJhhLJr8lAkSlvcgBHNhejKeOJ/WUJvmZ7bVX1Sy30Dzl27aGueBb1ve6Is27oycYkNliIpmOEFdhx/nNorGtanTzRCnZQDVmitsDtJU4PMXgjU3S/ZSusOipZAZ28sz7CeLLr//9SxnYVRR3ZRJBH9qAv8mR1RwYT7+av7XRFXGv9xnABFhQlInlGSOEtfMbIvKgCsq7JpQ17X4Evv/C2Netuu32pw5tiwD71EFJO6PsG7ioFbMycP96JZts8GSM4N3vdyNl0a7AShjTpUh7LD3vT6xeVtjbdgNvPZs6L8BcV0Mltyms=

Please visit www.eurid.eu for more info.'),
            [
                'domain.name' => 'Domain:',
                'domain.status' => 'Status:',
                'domain.nserver' => 'Name servers:',
                'domain.created' => 'Registered:',
                'domain.registrar' => 'Registrar:',
                'tech' => 'Registrar Technical Contacts:',
                'owner' => 'Registrant:',
                '' => 'Please visit',
            ],
        ];
    }

    /**
     * @todo find any domain with that fking data
     * @dataProvider dataProviderGetBlocks
     */
    public function testGetBlocks(array $rawData, array $items, bool $partialMatch = false, bool $defBlock = false): void
    {
        $r = \get_blocks($rawData, $items, $partialMatch, $defBlock);
        //\print_r($r);

        self::assertIsArray($r);
    }

    public function dataProviderShowHTML(): \Generator
    {
        yield [
            [
                'rawdata' => [],
                'regrinfo' => [],
                'regyinfo' => [],
            ],
            '',
        ];

        yield [
            [
                'rawdata' => [
                    'Ref: 62.0.0.0',
                ],
                'regrinfo' => [],
                'regyinfo' => [],
            ],
            '<b>Ref: </b>62.0.0.0<br />',
        ];

        yield [
            [
                'rawdata' => [
                    'Ref:            https://rdap.arin.net/registry/ip/62.0.0.0',
                ],
                'regrinfo' => [],
                'regyinfo' => [],
            ],
            '<b>Ref:            </b>62.0.0.0<br />',
        ];

        yield [
            [
                'rawdata' => [
                    'Ref:            https://rdap.arin.net/registry/ip/62.0.0.0',
                ],
                'regrinfo' => [],
                'regyinfo' => [],
            ],
            '<b>Ref:            </b><a href="https://example.com/test-page?query=62.0.0.0">62.0.0.0</a><br />',
            'https://example.com/test-page',
        ];
    }

    /**
     * @dataProvider dataProviderShowHTML
     */
    public function testShowHTML(array $data, string $expectedResult, ?string $useLink = null): void
    {
        $utils = new \WhoisUtils();
        $resultHtml = $utils->showHTML($data, $useLink);

        self::assertSame($expectedResult, $resultHtml);
    }
}
