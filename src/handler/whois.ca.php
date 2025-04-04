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

if (!\defined('__CA_HANDLER__')) {
    \define('__CA_HANDLER__', 1);
}

final class ca_handler extends WhoisHandlerAbstract
{
    public function parse(Whois $whoisClient, array $data_str, $query): ?array
    {
        $r = [];
        $items = [
            'owner' => 'Registrant:',
            'admin' => 'Administrative contact:',
            'tech' => 'Technical contact:',
            'domain.sponsor' => 'Registrar:',
            'domain.nserver' => 'Name servers:',
            'domain.status' => 'Domain status:',
            'domain.created' => 'Creation date:',
            'domain.expires' => 'Expiry date:',
            'domain.changed' => 'Updated date:',
        ];

        $extra = [
            'postal address:' => 'address.0',
            'job title:' => '',
            'number:' => 'handle',
            'description:' => 'organization',
        ];

        $r['regrinfo'] = WhoisParser::easy_parser($data_str['rawdata'], $items, 'ymd', $extra);

        if (!empty($r['regrinfo']['domain']['sponsor'])) {
            [$v, $reg] = \explode(':', $r['regrinfo']['domain']['sponsor'][0]);
            $r['regrinfo']['domain']['sponsor'] = \trim($reg);
        }

        if (empty($r['regrinfo']['domain']['status']) || 'available' === $r['regrinfo']['domain']['status']) {
            $r['regrinfo']['registered'] = 'no';
        } else {
            $r['regrinfo']['registered'] = 'yes';
        }

        $r['regyinfo'] = [
            'registrar' => 'CIRA',
            'referrer' => 'http://www.cira.ca/',
        ];

        return $r;
    }
}
