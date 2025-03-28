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

if (!\defined('__ZANET_HANDLER__')) {
    \define('__ZANET_HANDLER__', 1);
}

final class zanet_handler extends WhoisHandlerAbstract
{
    public function parse(Whois $whoisClient, array $data_str, $query): ?array
    {
        $r = [];
        $items = [
            'domain.name' => 'Domain Name            : ',
            'domain.created' => 'Record Created         :',
            'domain.changed' => 'Record	Last Updated    :',
            'owner.name' => 'Registered for         :',
            'admin' => 'Administrative Contact :',
            'tech' => 'Technical Contact      :',
            'domain.nserver' => 'Domain Name Servers listed in order:',
            'registered' => 'No such domain: ',
            '' => 'The ZA NiC whois',
        ];

        // Arrange contacts ...

        $rawdata = [];

        foreach ($data_str['rawdata'] as $line) {
            if (\str_contains($line, ' Contact ')) {
                $pos = \strpos($line, ':');

                if (false !== $pos) {
                    $rawdata[] = \substr($line, 0, $pos + 1);
                    $rawdata[] = \trim(\substr($line, $pos + 1));

                    continue;
                }
            }
            $rawdata[] = $line;
        }

        $r['regrinfo'] = WhoisParser::get_blocks($rawdata, $items);

        if (isset($r['regrinfo']['registered'])) {
            $r['regrinfo']['registered'] = 'no';
        } else {
            if (isset($r['regrinfo']['admin'])) {
                $r['regrinfo']['admin'] = WhoisParser::get_contact($r['regrinfo']['admin']);
            }

            if (isset($r['regrinfo']['tech'])) {
                $r['regrinfo']['tech'] = WhoisParser::get_contact($r['regrinfo']['tech']);
            }
        }

        $r['regyinfo']['referrer'] = 'http://www.za.net/'; // or http://www.za.org
        $r['regyinfo']['registrar'] = 'ZA NiC';

        return WhoisParser::format_dates($r, 'xmdxxy');
    }
}
