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

if (!\defined('__IP_HANDLER__')) {
    \define('__IP_HANDLER__', 1);
}

final class ip_handler extends WhoisHandlerAbstract
{
    public string $HANDLER_VERSION = '1.0';

    public array $REGISTRARS = [
        'European Regional Internet Registry/RIPE NCC' => 'whois.ripe.net',
        'RIPE Network Coordination Centre' => 'whois.ripe.net',
        'Asia Pacific Network Information	Center' => 'whois.apnic.net',
        'Asia Pacific Network Information Centre' => 'whois.apnic.net',
        'Latin American and Caribbean IP address Regional Registry' => 'whois.lacnic.net',
        'African Network Information Center' => 'whois.afrinic.net',
    ];

    public array $HANDLERS = [
        'whois.krnic.net' => 'krnic',
        'whois.apnic.net' => 'apnic',
        'whois.ripe.net' => 'ripe',
        'whois.arin.net' => 'arin',
        'whois.lacnic.net' => 'lacnic',
        'whois.afrinic.net' => 'afrinic',
    ];

    public array $more_data = [];    // More queries to get more accurated data
    public array $done = [];

    public function parse(Whois $whoisClient, array $data_str, $query): ?array
    {
        $result = [];
        $result['regrinfo'] = [];
        $result['regyinfo'] = [];
        $result['regyinfo']['registrar'] = 'American Registry for Internet Numbers (ARIN)';
        $result['rawdata'] = [];

        if (!\str_contains($query, '.')) {
            $result['regyinfo']['type'] = 'AS';
        } else {
            $result['regyinfo']['type'] = 'ip';
        }

        if (!$whoisClient->deepWhois) {
            return null;
        }

        $whoisClient->Query = [];
        $whoisClient->Query['server'] = 'whois.arin.net';
        $whoisClient->Query['query'] = $query;

        $rawdata = $data_str['rawdata'];

        if (empty($rawdata)) {
            return $result;
        }

        $presults = [];
        $presults[] = $rawdata;
        $ip = \ip2long($query);
        $done = [];

        while (\count($presults) > 0) {
            $rwdata = \array_shift($presults);
            $found = false;

            foreach ($rwdata as $line) {
                if (!\strncmp($line, 'American Registry for Internet Numbers', 38)) {
                    continue;
                }

                $p = \strpos($line, '(NETBLK-');

                if (false === $p) {
                    $p = \strpos($line, '(NET-');
                }

                if (false !== $p) {
                    $net = \strtok(\substr($line, $p + 1), ') ');
                    $postNet = \substr($line, $p + \strlen($net) + 3);

                    if (false !== $postNet) {
                        [$low, $high] = \explode('-', \str_replace(' ', '', $postNet));

                        if (!isset($done[$net]) && $ip >= \ip2long($low) && $ip <= \ip2long($high)) {
                            if (!empty($this->REGISTRARS['owner'])) {
                                $this->handle_rwhois($this->REGISTRARS['owner'], $query);

                                break 2;
                            }
                            $whoisClient->Query['args'] = 'n '.$net;
                            $presults[] = $whoisClient->GetRawData($net);
                            $done[$net] = 1;
                        }
                    }
                    $found = true;
                }
            }

            if (!$found) {
                $whoisClient->Query['file'] = 'whois.ip.arin.php';
                $whoisClient->Query['handler'] = 'arin';
                $result = $this->parse_results($whoisClient, $result, $rwdata, $query, true);
            }
        }

        unset($whoisClient->Query['args']);

        while (\count($this->more_data) > 0) {
            $srv_data = \array_shift($this->more_data);
            $whoisClient->Query['server'] = $srv_data['server'];
            unset($whoisClient->Query['handler']);
            // Use original query
            $rwdata = $whoisClient->GetRawData($srv_data['query']);

            if (!empty($rwdata)) {
                if (!empty($srv_data['handler'])) {
                    $whoisClient->Query['handler'] = $srv_data['handler'];

                    if (!empty($srv_data['file'])) {
                        $whoisClient->Query['file'] = $srv_data['file'];
                    } else {
                        $whoisClient->Query['file'] = 'whois.'.$whoisClient->Query['handler'].'.php';
                    }
                }

                $result = $this->parse_results($whoisClient, $result, $rwdata, $query, $srv_data['reset']);
                $whoisClient->setWhoisInfo($result);
            }
        }

        // Normalize nameserver fields

        if (isset($result['regrinfo']['network']['nserver'])) {
            if (!\is_array($result['regrinfo']['network']['nserver'])) {
                unset($result['regrinfo']['network']['nserver']);
            } else {
                $result['regrinfo']['network']['nserver'] = $whoisClient->FixNameServer($result['regrinfo']['network']['nserver']);
            }
        }

        return $result;
    }

    // -----------------------------------------------------------------

    private function handle_rwhois(string $server, string $query): void
    {
        // Avoid querying the same server twice

        $parts = \parse_url($server);

        if (empty($parts['host'])) {
            $host = $parts['path'];
        } else {
            $host = $parts['host'];
        }

        if (\array_key_exists($host, $this->done)) {
            return;
        }

        $q = [
            'query' => $query,
            'server' => $server,
        ];

        if (isset($this->HANDLERS[$host])) {
            $q['handler'] = $this->HANDLERS[$host];
            $q['file'] = \sprintf('whois.ip.%s.php', $q['handler']);
            $q['reset'] = true;
        } else {
            $q['handler'] = 'rwhois';
            $q['reset'] = false;
            unset($q['file']);
        }

        $this->more_data[] = $q;
        $this->done[$host] = 1;
    }

    // -----------------------------------------------------------------

    private function parse_results(Whois $whoisClient, array $result, array $rwdata, string $query, bool $reset): array
    {
        $rwres = $whoisClient->Process($rwdata);

        if ('AS' === $result['regyinfo']['type'] && !empty($rwres['regrinfo']['network'])) {
            $rwres['regrinfo']['AS'] = $rwres['regrinfo']['network'];
            unset($rwres['regrinfo']['network']);
        }

        if ($reset) {
            $result['regrinfo'] = $rwres['regrinfo'];
            $result['rawdata'] = $rwdata;
        } else {
            $result['rawdata'][] = '';

            foreach ($rwdata as $line) {
                $result['rawdata'][] = $line;
            }

            foreach ($rwres['regrinfo'] as $key => $_) {
                $result = $this->join_result($result, $key, $rwres);
            }
        }

        if ($whoisClient->deepWhois) {
            if (isset($rwres['regrinfo']['rwhois'])) {
                $this->handle_rwhois($rwres['regrinfo']['rwhois'], $query);
                unset($result['regrinfo']['rwhois']);
            } elseif (isset($rwres['regrinfo']['owner']['organization']) && $rwres['regrinfo']['owner']['organization']) {
                switch ($rwres['regrinfo']['owner']['organization']) {
                    case 'KRNIC':
                        $this->handle_rwhois('whois.krnic.net', $query);

                        break;

                    case 'African Network Information Center':
                        $this->handle_rwhois('whois.afrinic.net', $query);

                        break;
                }
            }
        }

        if (!empty($rwres['regyinfo'])) {
            $result['regyinfo'] = \array_merge($result['regyinfo'], $rwres['regyinfo']);
        }

        return $result;
    }

    // -----------------------------------------------------------------

    private function join_result(array $result, string $key, array $newres): array
    {
        if (isset($result['regrinfo'][$key]) && !\array_key_exists(0, $result['regrinfo'][$key])) {
            $r = $result['regrinfo'][$key];
            $result['regrinfo'][$key] = [$r];
        }

        $result['regrinfo'][$key][] = $newres['regrinfo'][$key];

        return $result;
    }
}
