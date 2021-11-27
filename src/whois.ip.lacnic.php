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

if (!\defined('__LACNIC_HANDLER__')) {
    \define('__LACNIC_HANDLER__', 1);
}

class lacnic_handler
{
    public function parse($data_str, $query)
    {
        $translate = [
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl-br' => 'handle',
            'nic-hdl' => 'handle',
            'person' => 'name',
            'netname' => 'name',
            'descr' => 'desc',
            'country' => 'address.country',
        ];

        $contacts = [
            'owner-c' => 'owner',
            'tech-c' => 'tech',
            'abuse-c' => 'abuse',
            'admin-c' => 'admin',
        ];

        $r = \generic_parser_a($data_str, $translate, $contacts, 'network');

        unset($r['network']['owner'], $r['network']['ownerid'], $r['network']['responsible'], $r['network']['address'], $r['network']['phone'], $r['network']['aut-num'], $r['network']['nsstat'], $r['network']['nslastaa'], $r['network']['inetrev']);

        if (!empty($r['network']['aut-num'])) {
            $r['network']['handle'] = $r['network']['aut-num'];
        }

        if (isset($r['network']['nserver'])) {
            $r['network']['nserver'] = \array_unique($r['network']['nserver']);
        }

        $r = ['regrinfo' => $r];
        $r['regyinfo']['type'] = 'ip';
        $r['regyinfo']['registrar'] = 'Latin American and Caribbean IP address Regional Registry';

        return $r;
    }
}
