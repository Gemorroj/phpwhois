<?php

/**
 * PHPWhois IR Lookup Extension - http://github.com/sepehr/phpwhois-ir.
 *
 * An extension to PHPWhois (http://phpwhois.org) library to support IR lookups.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

// Define the handler flag.
if (!\defined('__IR_HANDLER__')) {
    \define('__IR_HANDLER__', 1);
}

final class ir_handler extends WhoisHandlerAbstract
{
    public function parse(Whois $whoisClient, array $data_str, $query): ?array
    {
        $r = [];
        $translate = [
            'nic-hdl' => 'handle',
            'org' => 'organization',
            'e-mail' => 'email',
            'person' => 'name',
            'fax-no' => 'fax',
            'domain' => 'name',
        ];

        $contacts = [
            'admin-c' => 'admin',
            'tech-c' => 'tech',
            'holder-c' => 'owner',
        ];

        $reg = WhoisParser::generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'Ymd');

        $r['regrinfo'] = $reg;
        $r['regyinfo'] = [
            'referrer' => 'http://whois.nic.ir/',
            'registrar' => 'NIC-IR',
        ];

        return $r;
    }
}
