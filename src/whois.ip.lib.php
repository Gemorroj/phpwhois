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

//-----------------------------------------------------------------
// Check if ip adddress is valid

function phpwhois_validip($ip)
{
    if (empty($ip)) {
        return false;
    }

    if ((-1 == \ip2long($ip)) or (false === \ip2long($ip))) {
        return false;
    }

    $reserved_ips = [
        ['0.0.0.0', '2.255.255.255'],
        ['10.0.0.0', '10.255.255.255'],
        ['127.0.0.0', '127.255.255.255'],
        ['169.254.0.0', '169.254.255.255'],
        ['172.16.0.0', '172.31.255.255'],
        ['192.0.2.0', '192.0.2.255'],
        ['192.168.0.0', '192.168.255.255'],
        ['255.255.255.0', '255.255.255.255'],
    ];

    foreach ($reserved_ips as $r) {
        $min = \ip2long($r[0]);
        $max = \ip2long($r[1]);
        if ((\ip2long($ip) >= $min) && (\ip2long($ip) <= $max)) {
            return false;
        }
    }

    return true;
}

//-----------------------------------------------------------------
// Get real client ip address

function phpwhois_getclientip()
{
    if (!empty($_SERVER['HTTP_CLIENT_IP']) && phpwhois_validip($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    }

    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        foreach (\explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $ip) {
            if (phpwhois_validip(\trim($ip))) {
                return $ip;
            }
        }
    }

    if (!empty($_SERVER['HTTP_X_FORWARDED']) && phpwhois_validip($_SERVER['HTTP_X_FORWARDED'])) {
        return $_SERVER['HTTP_X_FORWARDED'];
    }

    if (!empty($_SERVER['HTTP_FORWARDED_FOR']) && phpwhois_validip($_SERVER['HTTP_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_FORWARDED_FOR'];
    }

    if (!empty($_SERVER['HTTP_FORWARDED']) && phpwhois_validip($_SERVER['HTTP_FORWARDED'])) {
        return $_SERVER['HTTP_FORWARDED'];
    }

    if (!empty($_SERVER['HTTP_X_FORWARDED']) && phpwhois_validip($_SERVER['HTTP_X_FORWARDED'])) {
        return $_SERVER['HTTP_X_FORWARDED'];
    }

    return $_SERVER['REMOTE_ADDR'];
}

//-----------------------------------------------------------------
// Convert from CIDR to net range

function phpwhois_cidr_conv($net)
{
    $start = \strtok($net, '/');
    $n = 3 - \substr_count($net, '.');

    if ($n > 0) {
        for ($i = $n; $i > 0; --$i) {
            $start .= '.0';
        }
    }

    $bits1 = \str_pad(\decbin(\ip2long($start)), 32, '0', 'STR_PAD_LEFT');
    $net = \pow(2, (32 - \substr(\strstr($net, '/'), 1))) - 1;
    $bits2 = \str_pad(\decbin($net), 32, '0', 'STR_PAD_LEFT');
    $final = '';

    for ($i = 0; $i < 32; ++$i) {
        if ($bits1[$i] == $bits2[$i]) {
            $final .= $bits1[$i];
        }
        if (1 == $bits1[$i] and 0 == $bits2[$i]) {
            $final .= $bits1[$i];
        }
        if (0 == $bits1[$i] and 1 == $bits2[$i]) {
            $final .= $bits2[$i];
        }
    }

    return $start.' - '.\long2ip(\bindec($final));
}
