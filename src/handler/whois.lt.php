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

if (!\defined('__LT_HANDLER__')) {
    \define('__LT_HANDLER__', 1);
}

final class lt_handler extends WhoisHandlerAbstract
{
    public function parse(Whois $whoisClient, array $data_str, $query): ?array
    {
        $r = [];
        $translate = [
            'contact nic-hdl:' => 'handle',
            'contact name:' => 'name',
        ];

        $items = [
            'admin' => 'Contact type:      Admin',
            'tech' => 'Contact type:      Tech',
            'zone' => 'Contact type:      Zone',
            'owner.name' => 'Registrar:',
            'owner.email' => 'Registrar email:',
            'domain.status' => 'Status:',
            'domain.created' => 'Registered:',
            'domain.changed' => 'Last updated:',
            'domain.nserver.' => 'NS:',
            '' => '%',
        ];

        $r['regrinfo'] = WhoisParser::easy_parser($data_str['rawdata'], $items, 'ymd', $translate);

        $r['regyinfo'] = [
            'referrer' => 'http://www.domreg.lt',
            'registrar' => 'DOMREG.LT',
        ];

        return $r;
    }
}
