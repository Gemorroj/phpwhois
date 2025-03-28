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

if (!\defined('__BR_HANDLER__')) {
    \define('__BR_HANDLER__', 1);
}

final class br_handler extends WhoisHandlerAbstract
{
    public function parse(Whois $whoisClient, array $data_str, $query): ?array
    {
        $a = [];
        $translate = [
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl-br' => 'handle',
            'person' => 'name',
            'netname' => 'name',
            'domain' => 'name',
            'updated' => '',
        ];

        $contacts = [
            'owner-c' => 'owner',
            'tech-c' => 'tech',
            'admin-c' => 'admin',
            'billing-c' => 'billing',
        ];

        $r = WhoisParser::generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'Ymd');

        if (\in_array('Permission denied.', $r['disclaimer'])) {
            $r['registered'] = 'unknown';

            return $r;
        }

        if (isset($r['domain']['nsstat'])) {
            unset($r['domain']['nsstat']);
        }
        if (isset($r['domain']['nslastaa'])) {
            unset($r['domain']['nslastaa']);
        }

        if (isset($r['domain']['owner'])) {
            $r['owner']['organization'] = $r['domain']['owner'];
            unset($r['domain']['owner']);
        }

        if (isset($r['domain']['responsible'])) {
            unset($r['domain']['responsible']);
        }
        if (isset($r['domain']['address'])) {
            unset($r['domain']['address']);
        }
        if (isset($r['domain']['phone'])) {
            unset($r['domain']['phone']);
        }

        $a['regrinfo'] = $r;
        $a['regyinfo'] = [
            'registrar' => 'BR-NIC',
            'referrer' => 'http://www.nic.br',
        ];

        return $a;
    }
}
