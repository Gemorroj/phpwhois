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

if (!\defined('__ORG_ZA_HANDLER__')) {
    \define('__ORG_ZA_HANDLER__', 1);
}

final class org_za_handler extends WhoisHandlerAbstract
{
    public function parse(Whois $whoisClient, array $data_str, $query): ?array
    {
        $r = [];
        $items = [
            'domain.status' => 'Status:',
            'domain.nserver' => 'Domain name servers in listed order:',
            'domain.changed' => 'Record last updated on',
            'owner' => 'rwhois search on',
            'admin' => 'Administrative Contact:',
            'tech' => 'Technical Contact:',
            'billing' => 'Billing Contact:',
            '#' => 'Search Again',
        ];

        $r['regrinfo'] = WhoisParser::get_blocks($data_str['rawdata'], $items);

        if (isset($r['regrinfo']['domain']['status'])) {
            $r['regrinfo']['registered'] = 'yes';
            $r['regrinfo']['domain']['handler'] = \strtok(\array_shift($r['regrinfo']['owner']), ' ');
            $r['regrinfo'] = WhoisParser::get_contacts($r['regrinfo']);
        } else {
            $r['regrinfo']['registered'] = 'no';
        }

        $r['regyinfo']['referrer'] = 'http://www.org.za';
        $r['regyinfo']['registrar'] = 'The ORG.ZA Domain';

        return $r;
    }
}
