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

if (!\defined('__COOP_HANDLER__')) {
    \define('__COOP_HANDLER__', 1);
}

final class coop_handler extends WhoisHandlerAbstract
{
    public function parse(Whois $whoisClient, array $data_str, $query): ?array
    {
        $r = [];
        $items = [
            'owner' => 'Contact Type:            registrant',
            'admin' => 'Contact Type:            admin',
            'tech' => 'Contact Type:            tech',
            'billing' => 'Contact Type:            billing',
            'domain.name' => 'Domain Name:',
            'domain.handle' => 'Domain ID:',
            'domain.expires' => 'Expiry Date:',
            'domain.created' => 'Created:',
            'domain.changed' => 'Last updated:',
            'domain.status' => 'Domain Status:',
            'domain.sponsor' => 'Sponsoring registrar:',
            'domain.nserver.' => 'Host Name:',
        ];

        $translate = [
            'Contact ID:' => 'handle',
            'Name:' => 'name',
            'Organisation:' => 'organization',
            'Street 1:' => 'address.street.0',
            'Street 2:' => 'address.street.1',
            'Street 3:' => 'address.street.2',
            'City:' => 'address.city',
            'State/Province:' => 'address.state',
            'Postal code:' => 'address.pcode',
            'Country:' => 'address.country',
            'Voice:' => 'phone',
            'Fax:' => 'fax',
            'Email:' => 'email',
        ];

        $blocks = WhoisParser::get_blocks($data_str['rawdata'], $items);

        $r = [];

        if (isset($blocks['domain'])) {
            $r['regrinfo']['domain'] = WhoisParser::format_dates($blocks['domain'], 'dmy');
            $r['regrinfo']['registered'] = 'yes';

            if (isset($blocks['owner'])) {
                $r['regrinfo']['owner'] = WhoisParser::generic_parser_b($blocks['owner'], $translate, 'dmy', false);

                if (isset($blocks['tech'])) {
                    $r['regrinfo']['tech'] = WhoisParser::generic_parser_b($blocks['tech'], $translate, 'dmy', false);
                }

                if (isset($blocks['admin'])) {
                    $r['regrinfo']['admin'] = WhoisParser::generic_parser_b($blocks['admin'], $translate, 'dmy', false);
                }

                if (isset($blocks['billing'])) {
                    $r['regrinfo']['billing'] = WhoisParser::generic_parser_b($blocks['billing'], $translate, 'dmy', false);
                }
            } else {
                $r['regrinfo']['owner'] = WhoisParser::generic_parser_b($data_str['rawdata'], $translate, 'dmy', false);
            }
        } else {
            $r['regrinfo']['registered'] = 'no';
        }

        $r['regyinfo'] = [
            'referrer' => 'http://www.nic.coop',
            'registrar' => '.coop registry',
        ];

        return $r;
    }
}
