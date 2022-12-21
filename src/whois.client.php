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

abstract class WhoisClient
{
    // Recursion allowed ?
    public bool $gtld_recurse = true;

    // Default WHOIS port
    public int $PORT = 43;

    // Maximum number of retries on connection failure
    public int $RETRY = 0;

    // Time to wait between retries
    public int $SLEEP = 2;

    // Read buffer size (0 == char by char)
    public int $BUFFER = 1024;

    // Communications timeout
    public int $STIMEOUT = 10;

    // List of servers and handlers (loaded from servers.whois)
    public array $DATA = [
        'bz' => 'gtld',
        'com' => 'gtld',
        'jobs' => 'gtld',
        'li' => 'ch',
        'net' => 'gtld',
        'su' => 'ru',
        'tv' => 'gtld',
        'za.org' => 'zanet',
        'za.net' => 'zanet',
        // Punicode
        'xn--p1ai' => 'ru',
    ];

    // Array to contain all query variables
    public array $Query = [
        'tld' => '',
        'type' => 'domain',
        'query' => '',
        'status' => null,
        'server' => null,
        'errstr' => null,
    ];

    // This release of the package
    public string $CODE_VERSION = '4.2.2';

    public string $DATA_VERSION = '19';

    // handled gTLD whois servers
    public array $WHOIS_GTLD_HANDLER = [
        'whois.bulkregister.com' => 'enom',
        'whois.dotregistrar.com' => 'dotster',
        'whois.namesdirect.com' => 'dotster',
        'whois.psi-usa.info' => 'psiusa',
        'whois.www.tv' => 'tvcorp',
        'whois.tucows.com' => 'opensrs',
        'whois.35.com' => 'onlinenic',
        'whois.nominalia.com' => 'genericb',
        'whois.encirca.com' => 'genericb',
        'whois.corenic.net' => 'genericb',
    ];
    // Non UTF-8 servers
    public array $NON_UTF8 = [
        'br.whois-servers.net' => 1,
        'ca.whois-servers.net' => 1,
        'cl.whois-servers.net' => 1,
        'hu.whois-servers.net' => 1,
        'is.whois-servers.net' => 1,
        'pt.whois-servers.net' => 1,
        'whois.interdomain.net' => 1,
        'whois.lacnic.net' => 1,
        'whois.nicline.com' => 1,
        'whois.ripe.net' => 1,
    ];
    public bool $deep_whois = true;
    // Non ICANN TLD's
    public array $WHOIS_NON_ICANN = [
        'agent' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'agente' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'america' => 'http://www.adns.net/whois.php?txtDOMAIN={domain}.{tld}',
        'amor' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'amore' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'amour' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'arte' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'artes' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'arts' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'asta' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'auction' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'auktion' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'boutique' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'chat' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'chiesa' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'church' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'cia' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'ciao' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'cie' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'club' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'clube' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'com2' => 'http://www.adns.net/whois.php?txtDOMAIN={domain}.{tld}',
        'deporte' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'ditta' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'earth' => 'http://www.adns.net/whois.php?txtDOMAIN={domain}.{tld}',
        'eglise' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'enchere' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'escola' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'escuela' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'esporte' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'etc' => 'http://www.adns.net/whois.php?txtDOMAIN={domain}.{tld}',
        'famiglia' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'familia' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'familie' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'family' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'free' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'hola' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'game' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'ges' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'gmbh' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'golf' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'gratis' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'gratuit' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'iglesia' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'igreja' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'inc' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'jeu' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'jogo' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'juego' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'kids' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'kirche' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'krunst' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'law' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'legge' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'lei' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'leilao' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'ley' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'liebe' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'lion' => 'http://www.adns.net/whois.php?txtDOMAIN={domain}.{tld}',
        'llc' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'llp' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'loi' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'loja' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'love' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'ltd' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'makler' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'med' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'mp3' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'not' => 'http://www.adns.net/whois.php?txtDOMAIN={domain}.{tld}',
        'online' => 'http://www.adns.net/whois.php?txtDOMAIN={domain}.{tld}',
        'recht' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'reise' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'resto' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'school' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'schule' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'scifi' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'scuola' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'shop' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'soc' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'spiel' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'sport' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'subasta' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'tec' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'tech' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'tienda' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'travel' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'turismo' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'usa' => 'http://www.adns.net/whois.php?txtDOMAIN={domain}.{tld}',
        'verein' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'viaje' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'viagem' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'video' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'voyage' => 'http://www.new.net/search_whois.tp?domain={domain}&tld={tld}',
        'z' => 'http://www.adns.net/whois.php?txtDOMAIN={domain}.{tld}',
    ];
    // TLD's that have special whois servers or that can only be reached via HTTP
    public array $WHOIS_SPECIAL = [
        'ad' => '',
        'ae' => 'whois.aeda.net.ae',
        'af' => 'whois.nic.af',
        'ai' => 'http://whois.offshore.ai/cgi-bin/whois.pl?domain-name={domain}.ai',
        'al' => '',
        'az' => '',
        'ba' => '',
        'bb' => 'http://domains.org.bb/regsearch/getdetails.cfm?DND={domain}.bb',
        'bg' => 'http://www.register.bg/bg-nic/displaydomain.pl?domain={domain}.bg&search=exist',
        'bh' => 'whois.nic.bh',
        'bi' => 'whois.nic.bi',
        'bj' => 'whois.nic.bj',
        'by' => '',
        'bz' => 'whois2.afilias-grs.net',
        'cy' => '',
        'es' => '',
        'fj' => 'whois.usp.ac.fj',
        'fm' => 'http://www.dot.fm/query_whois.cfm?domain={domain}&tld=fm',
        'jobs' => 'jobswhois.verisign-grs.com',
        'ke' => 'kenic.or.ke',
        'la' => 'whois.centralnic.net',
        'gr' => '',
        'gs' => 'http://www.adamsnames.tc/whois/?domain={domain}.gs',
        'gt' => 'http://www.gt/Inscripcion/whois.php?domain={domain}.gt',
        'me' => 'whois.meregistry.net',
        'mobi' => 'whois.dotmobiregistry.net',
        'ms' => 'http://www.adamsnames.tc/whois/?domain={domain}.ms',
        'mt' => 'http://www.um.edu.mt/cgi-bin/nic/whois?domain={domain}.mt',
        'nl' => 'whois.domain-registry.nl',
        'ly' => 'whois.nic.ly',
        'pe' => 'kero.rcp.net.pe',
        'pr' => 'whois.uprr.pr',
        'pro' => 'whois.registry.pro',
        'sc' => 'whois2.afilias-grs.net',
        'tc' => 'http://www.adamsnames.tc/whois/?domain={domain}.tc',
        'tf' => 'http://www.adamsnames.tc/whois/?domain={domain}.tf',
        've' => 'whois.nic.ve',
        'vg' => 'http://www.adamsnames.tc/whois/?domain={domain}.vg',
        // Second level
        'net.au' => 'whois.aunic.net',
        'ae.com' => 'whois.centralnic.net',
        'br.com' => 'whois.centralnic.net',
        'cn.com' => 'whois.centralnic.net',
        'de.com' => 'whois.centralnic.net',
        'eu.com' => 'whois.centralnic.net',
        'hu.com' => 'whois.centralnic.net',
        'jpn.com' => 'whois.centralnic.net',
        'kr.com' => 'whois.centralnic.net',
        'gb.com' => 'whois.centralnic.net',
        'no.com' => 'whois.centralnic.net',
        'qc.com' => 'whois.centralnic.net',
        'ru.com' => 'whois.centralnic.net',
        'sa.com' => 'whois.centralnic.net',
        'se.com' => 'whois.centralnic.net',
        'za.com' => 'whois.centralnic.net',
        'uk.com' => 'whois.centralnic.net',
        'us.com' => 'whois.centralnic.net',
        'uy.com' => 'whois.centralnic.net',
        'gb.net' => 'whois.centralnic.net',
        'se.net' => 'whois.centralnic.net',
        'uk.net' => 'whois.centralnic.net',
        'za.net' => 'whois.za.net',
        'za.org' => 'whois.za.net',
        'co.za' => 'http://co.za/cgi-bin/whois.sh?Domain={domain}.co.za',
        'org.za' => 'http://www.org.za/cgi-bin/rwhois?domain={domain}.org.za&format=full',
    ];
    // If whois Server needs any parameters, enter it here
    public array $WHOIS_PARAM = [
        'com.whois-servers.net' => 'domain =$',
        'net.whois-servers.net' => 'domain =$',
        'de.whois-servers.net' => '-T dn,ace $',
        'jp.whois-servers.net' => 'DOM $/e',
    ];

    // Full code and data version string (e.g. 'Whois2.php v3.01:16')
    public string $VERSION;

    // Constructor function
    public function __construct()
    {
        // Set version
        $this->VERSION = \sprintf('phpWhois v%s-%s', $this->CODE_VERSION, $this->DATA_VERSION);
    }

    // Perform lookup
    protected function GetData(string $query = '', bool $deep_whois = true): array
    {
        $this->deep_whois = $deep_whois;
        // If domain to query passed in, use it, otherwise use domain from initialisation
        $query = !empty($query) ? $query : $this->Query['query'];

        $output = $this->GetRawData($query);

        // Create result and set 'rawdata'
        $result = ['rawdata' => $output];
        $this->set_whois_info($result);

        // Return now on error
        if (empty($output)) {
            return $result;
        }

        // If we have a handler, post-process it with it
        if (isset($this->Query['handler'])) {
            // Keep server list
            $servers = $result['regyinfo']['servers'];
            unset($result['regyinfo']['servers']);

            // Process data
            $result = $this->Process($result, $deep_whois);

            // Add new servers to the server list
            if (isset($result['regyinfo']['servers'])) {
                $result['regyinfo']['servers'] = \array_merge($servers, $result['regyinfo']['servers']);
            } else {
                $result['regyinfo']['servers'] = $servers;
            }

            // Handler may forget to set rawdata
            if (!isset($result['rawdata'])) {
                $result['rawdata'] = $output;
            }
        }

        // Type defaults to domain
        if (!isset($result['regyinfo']['type'])) {
            $result['regyinfo']['type'] = 'domain';
        }

        // Add error information if any
        if (isset($this->Query['errstr'])) {
            $result['errstr'] = $this->Query['errstr'];
        }

        // Fix/add nameserver information
        if (!isset($this->Query['tld']) || 'ip' !== $this->Query['tld']) {
            $this->FixResult($result, $query);
        }

        return $result;
    }

    abstract protected function FixResult(array &$result, string $domain): void;

    /*
     * Perform lookup. Returns an array. The 'rawdata' element contains an
     * array of lines gathered from the whois query. If a top level domain
     * handler class was found for the domain, other elements will have been
     * populated too.
     */
    public function GetRawData(string $query): array
    {
        $this->Query['query'] = $query;

        // clear error description
        if (isset($this->Query['errstr'])) {
            $this->Query['errstr'] = null;
        }

        if (!isset($this->Query['server'])) {
            $this->Query['status'] = 'error';
            $this->Query['errstr'][] = 'No server specified';

            return [];
        }

        // Check if protocol is http

        if (0 === \strpos($this->Query['server'], 'http://') || 0 === \strpos($this->Query['server'], 'https://')) {
            $output = $this->httpQuery();

            if (!$output) {
                $this->Query['status'] = 'error';
                $this->Query['errstr'][] = 'Connect failed to: '.$this->Query['server'];

                return [];
            }

            $this->Query['args'] = \substr(\strchr($this->Query['server'], '?'), 1);
            $this->Query['server'] = \strtok($this->Query['server'], '?');

            if (0 === \strpos($this->Query['server'], 'http://')) {
                $this->Query['server_port'] = 80;
            } else {
                $this->Query['server_port'] = 483;
            }
        } else {
            // Get args

            if (\strpos($this->Query['server'], '?')) {
                $parts = \explode('?', $this->Query['server']);
                $this->Query['server'] = \trim($parts[0]);
                $query_args = \trim($parts[1]);

                // replace substitution parameters
                $query_args = \str_replace('{query}', $query, $query_args);
                $query_args = \str_replace('{version}', 'phpWhois'.$this->CODE_VERSION, $query_args);

                if (false !== \strpos($query_args, '{ip}')) {
                    $query_args = \str_replace('{ip}', $this->getClientIp(), $query_args);
                }

                if (false !== \strpos($query_args, '{hname}')) {
                    $query_args = \str_replace('{hname}', \gethostbyaddr($this->getClientIp()), $query_args);
                }
            } else {
                if (empty($this->Query['args'])) {
                    $query_args = $query;
                } else {
                    $query_args = $this->Query['args'];
                }
            }

            $this->Query['args'] = $query_args;

            if (0 === \strpos($this->Query['server'], 'rwhois://')) {
                $this->Query['server'] = \substr($this->Query['server'], 9);
            }

            if (0 === \strpos($this->Query['server'], 'whois://')) {
                $this->Query['server'] = \substr($this->Query['server'], 8);
            }

            // Get port

            if (\strpos($this->Query['server'], ':')) {
                $parts = \explode(':', $this->Query['server']);
                $this->Query['server'] = \trim($parts[0]);
                $this->Query['server_port'] = \trim($parts[1]);
            } else {
                $this->Query['server_port'] = $this->PORT;
            }

            // Connect to whois server, or return if failed

            $ptr = $this->Connect();

            if ($ptr < 0) {
                $this->Query['status'] = 'error';
                $this->Query['errstr'][] = 'Connect failed to: '.$this->Query['server'];

                return [];
            }

            \stream_set_timeout($ptr, $this->STIMEOUT);
            \stream_set_blocking($ptr, 0);

            // Send query
            \fwrite($ptr, \trim($query_args)."\r\n");

            // Prepare to receive result
            $raw = '';
            $start = \time();
            $null = null;
            $r = [$ptr];

            while (!\feof($ptr)) {
                if (\stream_select($r, $null, $null, $this->STIMEOUT)) {
                    $raw .= \fgets($ptr, $this->BUFFER);
                }

                if (\time() - $start > $this->STIMEOUT) {
                    $this->Query['status'] = 'error';
                    $this->Query['errstr'][] = 'Timeout reading from '.$this->Query['server'];

                    return [];
                }
            }

            if (\array_key_exists($this->Query['server'], $this->NON_UTF8)) {
                $raw = \utf8_encode($raw);
            }

            $output = \explode("\n", $raw);

            // Drop empty last line (if it's empty! - saleck)
            if (empty($output[\count($output) - 1])) {
                unset($output[\count($output) - 1]);
            }
        }

        return $output;
    }

    protected function httpQuery(): ?array
    {
        $lines = @\file($this->Query['server']);

        if (!$lines) {
            return null;
        }

        $output = '';
        $pre = '';

        foreach ($lines as $val) {
            $val = \trim($val);

            $pos = \stripos($val, '<PRE>');
            if (false !== $pos) {
                $pre = "\n";
                $output .= \substr($val, 0, $pos)."\n";
                $val = \substr($val, $pos + 5);
            }
            $pos = \stripos($val, '</PRE>');
            if (false !== $pos) {
                $pre = '';
                $output .= \substr($val, 0, $pos)."\n";
                $val = \substr($val, $pos + 6);
            }
            $output .= $val.$pre;
        }

        $search = [
            '<BR>', '<P>', '</TITLE>',
            '</H1>', '</H2>', '</H3>',
            '<br>', '<p>', '</title>',
            '</h1>', '</h2>', '</h3>', ];

        $output = \str_replace($search, "\n", $output);
        $output = \str_replace('<TD', ' <td', $output);
        $output = \str_replace('<td', ' <td', $output);
        $output = \str_replace('<tr', "\n<tr", $output);
        $output = \str_replace('<TR', "\n<tr", $output);
        $output = \str_replace('&nbsp;', ' ', $output);
        $output = \strip_tags($output);
        $output = \explode("\n", $output);

        $rawdata = [];
        $null = 0;

        foreach ($output as $val) {
            $val = \trim($val);
            if ('' === $val) {
                if (++$null > 2) {
                    continue;
                }
            } else {
                $null = 0;
            }
            $rawdata[] = $val;
        }

        return $rawdata;
    }

    /**
     * Open a socket to the whois server.
     *
     * Returns a socket connection pointer on success, or -1 on failure.
     *
     * @return int|resource
     */
    protected function Connect()
    {
        $server = $this->Query['server'];

        // Fail if server not set
        if (!$server) {
            return -1;
        }

        // Get rid of protocol and/or get port
        $port = $this->Query['server_port'];

        $pos = \strpos($server, '://');

        if (false !== $pos) {
            $server = \substr($server, $pos + 3);
        }

        $pos = \strpos($server, ':');

        if (false !== $pos) {
            $port = \substr($server, $pos + 1);
            $server = \substr($server, 0, $pos);
        }

        // Enter connection attempt loop
        $retry = 0;

        while ($retry <= $this->RETRY) {
            // Set query status
            $this->Query['status'] = 'ready';

            // Connect to whois port
            $ptr = @\fsockopen($server, $port, $errno, $errstr, $this->STIMEOUT);

            if ($ptr > 0) {
                $this->Query['status'] = 'ok';

                return $ptr;
            }

            // Failed this attempt
            $this->Query['status'] = 'error';
            $this->Query['error'][] = $errstr;
            ++$retry;

            // Sleep before retrying
            \sleep($this->SLEEP);
        }

        // If we get this far, it hasn't worked
        return -1;
    }

    // Adds whois server query information to result
    public function set_whois_info(array &$result): void
    {
        $info = [
            'server' => $this->Query['server'],
        ];

        if (!empty($this->Query['args'])) {
            $info['args'] = $this->Query['args'];
        } else {
            $info['args'] = $this->Query['query'];
        }

        if (!empty($this->Query['server_port'])) {
            $info['port'] = $this->Query['server_port'];
        } else {
            $info['port'] = 43;
        }

        if (isset($result['regyinfo']['whois'])) {
            unset($result['regyinfo']['whois']);
        }

        if (isset($result['regyinfo']['rwhois'])) {
            unset($result['regyinfo']['rwhois']);
        }

        $result['regyinfo']['servers'][] = $info;
    }

    /*
     * Post-process result with handler class. On success, returns the result
     * from the handler. On failure, returns passed result unaltered.
     */
    public function Process(array &$result, bool $deep_whois = true): ?array
    {
        $this->deep_whois = $deep_whois;
        $handler_name = \str_replace('.', '_', $this->Query['handler']);

        // If the handler has not already been included somehow, include it now
        $HANDLER_FLAG = \sprintf('__%s_HANDLER__', \strtoupper($handler_name));

        if (!\defined($HANDLER_FLAG)) {
            include_once __DIR__.'/handler/'.$this->Query['file'];
        }

        // If the handler has still not been included, append to query errors list and return
        if (!\defined($HANDLER_FLAG)) {
            $this->Query['errstr'][] = "Can't find {$handler_name} handler: ".$this->Query['file'];

            return $result;
        }

        if (!$this->gtld_recurse && 'whois.gtld.php' === $this->Query['file']) {
            return $result;
        }

        // Pass result to handler
        $className = $handler_name.'_handler';

        /** @var WhoisHandler $handler */
        $handler = new $className();

        // Process
        return $handler->parse($this, $result, $this->Query['query']);
    }

    // Does more (deeper) whois ...
    public function DeepWhois(string $query, array $result): array
    {
        if (!isset($result['regyinfo']['whois'])) {
            return $result;
        }

        $this->Query['server'] = $wserver = $result['regyinfo']['whois'];
        unset($result['regyinfo']['whois']);
        $subresult = $this->GetRawData($query);

        if (!empty($subresult)) {
            $this->set_whois_info($result);
            $result['rawdata'] = $subresult;

            if (isset($this->WHOIS_GTLD_HANDLER[$wserver])) {
                $this->Query['handler'] = $this->WHOIS_GTLD_HANDLER[$wserver];
            } else {
                $parts = \explode('.', $wserver);
                $hname = \strtolower($parts[1]);

                if (($fp = @\fopen('whois.gtld.'.$hname.'.php', 'r', 1)) && \fclose($fp)) {
                    $this->Query['handler'] = $hname;
                }
            }

            if (!empty($this->Query['handler'])) {
                $this->Query['file'] = \sprintf('whois.gtld.%s.php', $this->Query['handler']);
                $regrinfo = $this->Process($subresult); // $result['rawdata']);
                $result['regrinfo'] = $this->merge_results($result['regrinfo'], $regrinfo);
                // $result['rawdata'] = $subresult;
            }
        }

        return $result;
    }

    // Merge results
    protected function merge_results(array $a1, array $a2): array
    {
        foreach ($a2 as $key => $val) {
            if (isset($a1[$key])) {
                if (\is_array($val)) {
                    if ('nserver' !== $key) {
                        $a1[$key] = $this->merge_results($a1[$key], $val);
                    }
                } else {
                    $val = \trim($val);
                    if ('' !== $val) {
                        $a1[$key] = $val;
                    }
                }
            } else {
                $a1[$key] = $val;
            }
        }

        return $a1;
    }

    public function FixNameServer(array $nserver): array
    {
        $dns = [];

        foreach ($nserver as $val) {
            $val = \str_replace(['[', ']', '(', ')'], '', \trim($val));
            $val = \str_replace("\t", ' ', $val);
            $parts = \explode(' ', $val);
            $host = '';
            $ip = '';

            foreach ($parts as $p) {
                if ('.' === \substr($p, -1)) {
                    $p = \substr($p, 0, -1);
                }

                $ipToLong = \ip2long($p);
                if (-1 === $ipToLong || false === $ipToLong) {
                    // Hostname ?
                    if ('' === $host && \preg_match('/^[\w\-]+(\.[\w\-]+)+$/', $p)) {
                        $host = $p;
                    }
                } else {
                    // IP Address
                    $ip = $p;
                }
            }

            // Valid host name ?

            if ('' === $host) {
                continue;
            }

            // Get ip address

            if ('' === $ip) {
                $ip = \gethostbyname($host);
                if ($ip === $host) {
                    $ip = '(DOES NOT EXIST)';
                }
            }

            if ('.' === $host[\strlen($host) - 1]) {
                $host = \substr($host, 0, -1);
            }

            $dns[\strtolower($host)] = $ip;
        }

        return $dns;
    }

    public function isValidIp(string $ip): bool
    {
        if (empty($ip)) {
            return false;
        }

        $ipLong = \ip2long($ip);

        if ((-1 === $ipLong) || (false === $ipLong)) {
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

            if (($ipLong >= $min) && ($ipLong <= $max)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get real client ip address.
     */
    public function getClientIp(): string
    {
        if (isset($_SERVER['HTTP_CLIENT_IP']) && $this->isValidIp($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        }

        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            foreach (\explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $ip) {
                if ($this->isValidIp(\trim($ip))) {
                    return $ip;
                }
            }
        }

        if (isset($_SERVER['HTTP_X_FORWARDED']) && $this->isValidIp($_SERVER['HTTP_X_FORWARDED'])) {
            return $_SERVER['HTTP_X_FORWARDED'];
        }

        if (isset($_SERVER['HTTP_FORWARDED_FOR']) && $this->isValidIp($_SERVER['HTTP_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_FORWARDED_FOR'];
        }

        if (isset($_SERVER['HTTP_FORWARDED']) && $this->isValidIp($_SERVER['HTTP_FORWARDED'])) {
            return $_SERVER['HTTP_FORWARDED'];
        }

        if (isset($_SERVER['HTTP_X_FORWARDED']) && $this->isValidIp($_SERVER['HTTP_X_FORWARDED'])) {
            return $_SERVER['HTTP_X_FORWARDED'];
        }

        return $_SERVER['REMOTE_ADDR'];
    }

    /**
     * Convert from CIDR to net range.
     */
    public function cidrToNetRange(string $net): string
    {
        $start = \strtok($net, '/');
        $n = 3 - \substr_count($net, '.');

        if ($n > 0) {
            for ($i = $n; $i > 0; --$i) {
                $start .= '.0';
            }
        }

        $bits1 = \str_pad(\decbin(\ip2long($start)), 32, '0', 'STR_PAD_LEFT');
        $net = 2 ** (32 - \substr(\strstr($net, '/'), 1)) - 1;
        $bits2 = \str_pad(\decbin($net), 32, '0', 'STR_PAD_LEFT');
        $final = '';

        for ($i = 0; $i < 32; ++$i) {
            if ($bits1[$i] == $bits2[$i]) {
                $final .= $bits1[$i];
            }
            if (1 == $bits1[$i] && 0 == $bits2[$i]) {
                $final .= $bits1[$i];
            }
            if (0 == $bits1[$i] && 1 == $bits2[$i]) {
                $final .= $bits2[$i];
            }
        }

        return $start.' - '.\long2ip(\bindec($final));
    }
}
