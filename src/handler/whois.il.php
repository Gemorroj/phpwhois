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

if (!\defined('__IL_HANDLER__')) {
    \define('__IL_HANDLER__', 1);
}

class il_handler extends WhoisHandlerAbstract
{
    public function parse(Whois $whoisClient, array $data_str, $query): ?array
    {
        $r = [];
        $translate = [
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl' => 'handle',
            'person' => 'name',
            'personname' => 'name',
            'address' => 'address', /*,
            'address' => 'address.city',
            'address' => 'address.pcode',
            'address' => 'address.country'*/
        ];

        $contacts = [
            'registrant' => 'owner',
            'admin-c' => 'admin',
            'tech-c' => 'tech',
            'billing-c' => 'billing',
            'zone-c' => 'zone',
        ];
        // unset($data_str['rawdata'][19]);
        \array_splice($data_str['rawdata'], 16, 1);
        \array_splice($data_str['rawdata'], 18, 1);

        $reg = WhoisParser::generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'Ymd');

        if (isset($reg['domain']['remarks'])) {
            unset($reg['domain']['remarks']);
        }

        if (isset($reg['domain']['descr:'])) {
            foreach ($reg['domain']['descr:'] as $key => $val) {
                $v = \trim(\substr(\strstr($val, ':'), 1));
                if (\str_contains($val, '[organization]:')) {
                    $reg['owner']['organization'] = $v;

                    continue;
                }
                if (\str_contains($val, '[phone]:')) {
                    $reg['owner']['phone'] = $v;

                    continue;
                }
                if (\str_contains($val, '[fax-no]:')) {
                    $reg['owner']['fax'] = $v;

                    continue;
                }
                if (\str_contains($val, '[e-mail]:')) {
                    $reg['owner']['email'] = $v;

                    continue;
                }

                $reg['owner']['address'][$key] = $v;
            }

            unset($reg['domain']['descr:']);
        }

        $r['regrinfo'] = $reg;
        $r['regyinfo'] = [
            'referrer' => 'http://www.isoc.org.il/',
            'registrar' => 'ISOC-IL',
        ];

        return $r;
    }
}
