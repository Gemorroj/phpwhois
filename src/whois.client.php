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

require_once 'whois.ip.lib.php';

class WhoisClient
{
    // Recursion allowed ?
    public $gtld_recurse = false;

    // Default WHOIS port
    public $PORT = 43;

    // Maximum number of retries on connection failure
    public $RETRY = 0;

    // Time to wait between retries
    public $SLEEP = 2;

    // Read buffer size (0 == char by char)
    public $BUFFER = 1024;

    // Communications timeout
    public $STIMEOUT = 10;

    // List of servers and handlers (loaded from servers.whois)
    public $DATA = [];

    // Array to contain all query variables
    public $Query = [
        'tld' => '',
        'type' => 'domain',
        'query' => '',
        'status' => null,
        'server' => null,
    ];

    // This release of the package
    public $CODE_VERSION = '4.2.2';

    public $DATA_VERSION;

    public $WHOIS_GTLD_HANDLER = [];
    public $NON_UTF8 = [];
    public $deep_whois = true;
    public $WHOIS_NON_ICANN = [];
    public $WHOIS_SPECIAL = [];
    public $WHOIS_PARAM = [];

    // Full code and data version string (e.g. 'Whois2.php v3.01:16')
    public $VERSION;

    // Constructor function
    public function __construct()
    {
        // Load DATA array
        require 'whois.servers.php';

        // Set version
        $this->VERSION = \sprintf('phpWhois v%s-%s', $this->CODE_VERSION, $this->DATA_VERSION);
    }

    // Perform lookup
    protected function GetData($query = '', $deep_whois = true): array
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
        if ('ip' !== $this->Query['tld'] && \method_exists($this, 'FixResult')) {
            $this->FixResult($result, $query);
        }

        return $result;
    }

    /*
     * Perform lookup. Returns an array. The 'rawdata' element contains an
     * array of lines gathered from the whois query. If a top level domain
     * handler class was found for the domain, other elements will have been
     * populated too.
     */
    protected function GetRawData($query): array
    {
        $this->Query['query'] = $query;

        // clear error description
        if (isset($this->Query['errstr'])) {
            unset($this->Query['errstr']);
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
                    $query_args = \str_replace('{ip}', phpwhois_getclientip(), $query_args);
                }

                if (false !== \strpos($query_args, '{hname}')) {
                    $query_args = \str_replace('{hname}', \gethostbyaddr(phpwhois_getclientip()), $query_args);
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

    /*
     * Open a socket to the whois server.
     *
     * Returns a socket connection pointer on success, or -1 on failure.
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
    protected function set_whois_info(&$result): void
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
    protected function Process(&$result, $deep_whois = true)
    {
        $this->deep_whois = $deep_whois;
        $handler_name = \str_replace('.', '_', $this->Query['handler']);

        // If the handler has not already been included somehow, include it now
        $HANDLER_FLAG = \sprintf('__%s_HANDLER__', \strtoupper($handler_name));

        if (!\defined($HANDLER_FLAG)) {
            include $this->Query['file'];
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
        $object = $handler_name.'_handler';

        $handler = new $object('');

        // If handler returned an error, append it to the query errors list
        if (isset($handler->Query['errstr'])) {
            $this->Query['errstr'][] = $handler->Query['errstr'];
        }

        $handler->deep_whois = $deep_whois;

        // Process
        return $handler->parse($result, $this->Query['query']);
    }

    // Does more (deeper) whois ...
    protected function DeepWhois($query, $result)
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
                $regrinfo = $this->Process($subresult); //$result['rawdata']);
                $result['regrinfo'] = $this->merge_results($result['regrinfo'], $regrinfo);
                //$result['rawdata'] = $subresult;
            }
        }

        return $result;
    }

    // Merge results
    protected function merge_results($a1, $a2)
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

    protected function FixNameServer($nserver)
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
}
