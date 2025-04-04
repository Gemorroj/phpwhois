<?php

/*
Whois.php        PHP classes to conduct whois queries

Copyright (C)1999,2005 easyDNS Technologies Inc. & Mark Jeftovic

Maintained by David Saez

For the most recent version of this package visit:

http://www.phpwhois.org

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

if (!\defined('__GTLD_HANDLER__')) {
    \define('__GTLD_HANDLER__', 1);
}

final class gtld_handler extends WhoisHandlerAbstract
{
    public string $HANDLER_VERSION = '1.1';
    public string $SUBVERSION;
    public array $result;

    public $REG_FIELDS = [
        'Domain Name:' => 'regrinfo.domain.name',
        'Registrar:' => 'regyinfo.registrar',
        'Whois Server:' => 'regyinfo.whois',
        'Referral URL:' => 'regyinfo.referrer',
        'Name Server:' => 'regrinfo.domain.nserver.',  // identical descriptors
        'Updated Date:' => 'regrinfo.domain.changed',
        'Last Updated On:' => 'regrinfo.domain.changed',
        'EPP Status:' => 'regrinfo.domain.epp_status.',
        'Status:' => 'regrinfo.domain.status.',
        'Creation Date:' => 'regrinfo.domain.created',
        'Created On:' => 'regrinfo.domain.created',
        'Expiration Date:' => 'regrinfo.domain.expires',
        'No match for ' => 'nodomain',
    ];

    public function parse(Whois $whoisClient, array $data_str, $query): ?array
    {
        if (\is_array($query) && \array_key_exists('handler', $query)) {
            $this->SUBVERSION = \sprintf('%s-%s', $query['handler'], $this->HANDLER_VERSION);
        }
        $this->result = WhoisParser::generic_parser_b($data_str['rawdata'], $this->REG_FIELDS, 'dmy');

        unset($this->result['registered']);

        if (isset($this->result['nodomain'])) {
            unset($this->result['nodomain']);
            $this->result['regrinfo']['registered'] = 'no';

            return $this->result;
        }

        if ($whoisClient->deepWhois) {
            $this->result = $whoisClient->DeepWhois($query, $this->result);
        }

        // Next server could fail to return data
        if (empty($this->result['rawdata']) || \count($this->result['rawdata']) < 3) {
            $this->result['rawdata'] = $data_str['rawdata'];
        }

        // Domain is registered no matter what next server says
        $this->result['regrinfo']['registered'] = 'yes';

        return $this->result;
    }
}
