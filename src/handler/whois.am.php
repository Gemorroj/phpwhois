<?php

if (!\defined('__AM_HANDLER__')) {
    \define('__AM_HANDLER__', 1);
}

class am_handler extends WhoisHandler
{
    public function parse(WhoisClient $whoisClient, array $data_str, $query): ?array
    {
        $r = [];
        $items = [
            'owner' => 'Registrant:',
            'domain.name' => 'Domain name:',
            'domain.created' => 'Registered:',
            'domain.changed' => 'Last modified:',
            'domain.nserver' => 'DNS servers:',
            'domain.status' => 'Status:',
            'tech' => 'Technical contact:',
            'admin' => 'Administrative contact:',
        ];

        $r['regrinfo'] = \get_blocks($data_str['rawdata'], $items);

        if (!empty($r['regrinfo']['domain']['name'])) {
            $r['regrinfo'] = \get_contacts($r['regrinfo']);
            $r['regrinfo']['registered'] = 'yes';
        } else {
            $r = [];
            $r['regrinfo']['registered'] = 'no';
        }

        $r['regyinfo'] = [
            'referrer' => 'http://www.isoc.am',
            'registrar' => 'ISOCAM',
        ];

        return $r;
    }
}