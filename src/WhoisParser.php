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

class WhoisParser
{
    public static function generic_parser_a(
        array $rawData,
        array $translate,
        array $contacts,
        string $main = 'domain',
        string $dateFormat = 'dmy'
    ): array {
        $ret = [];
        $disclaimer = [];
        $blocks = self::generic_parser_a_blocks($rawData, $translate, $disclaimer);

        if (isset($disclaimer) && \is_array($disclaimer)) {
            $ret['disclaimer'] = $disclaimer;
        }

        if (empty($blocks) || !\is_array($blocks['main'])) {
            $ret['registered'] = 'no';

            return $ret;
        }

        $r = $blocks['main'];
        $ret['registered'] = 'yes';

        foreach ($contacts as $key => $val) {
            if (isset($r[$key])) {
                if (\is_array($r[$key])) {
                    $blk = $r[$key][\count($r[$key]) - 1];
                } else {
                    $blk = $r[$key];
                }

                $blk = \strtoupper(\strtok($blk, ' '));
                if (isset($blocks[$blk])) {
                    $ret[$val] = $blocks[$blk];
                }
                unset($r[$key]);
            }
        }

        if ($main) {
            $ret[$main] = $r;
        }

        return self::format_dates($ret, $dateFormat);
    }

    public static function generic_parser_a_blocks(array $rawData, array $translate, array &$disclaimer): array
    {
        $newBlock = false;
        $hasData = false;
        $block = [];
        $blocks = [];
        $gKey = 'main';
        $dEnd = false;

        foreach ($rawData as $val) {
            $val = \trim($val);

            if ('' != $val && ('%' === $val[0] || '#' === $val[0])) {
                if (!$dEnd) {
                    $disclaimer[] = \trim(\substr($val, 1));
                }

                continue;
            }
            if ('' == $val) {
                $newBlock = true;

                continue;
            }
            if ($newBlock && $hasData) {
                $blocks[$gKey] = $block;
                $block = [];
                $gKey = '';
            }
            $dEnd = true;
            $newBlock = false;
            $k = \trim(\strtok($val, ':'));
            $v = \trim(\substr(\strstr($val, ':'), 1));

            if ('' == $v) {
                continue;
            }

            $hasData = true;

            if (isset($translate[$k])) {
                $k = $translate[$k];
                if ('' == $k) {
                    continue;
                }
                if (\str_contains($k, '.')) {
                    ${'block'.self::getVarName($k)} = $v;

                    continue;
                }
            } else {
                $k = \strtolower($k);
            }

            if ('handle' === $k) {
                $v = \strtok($v, ' ');
                $gKey = \strtoupper($v);
            }

            if (isset($block[$k]) && \is_array($block[$k])) {
                $block[$k][] = $v;
            } elseif (!isset($block[$k]) || '' == $block[$k]) {
                $block[$k] = $v;
            } else {
                $x = $block[$k];
                unset($block[$k]);
                $block[$k][] = $x;
                $block[$k][] = $v;
            }
        }

        if ($hasData) {
            $blocks[$gKey] = $block;
        }

        return $blocks;
    }

    public static function generic_parser_b(
        array $rawData,
        array $items = [],
        string $dateFormat = 'mdy',
        bool $hasReg = true,
        bool $scanAll = false
    ): array {
        if (!$items) {
            $items = [
                'Domain Name:' => 'domain.name',
                'Domain ID:' => 'domain.handle',
                'Sponsoring Registrar:' => 'domain.sponsor',
                'Registrar ID:' => 'domain.sponsor',
                'Domain Status:' => 'domain.status.',
                'Status:' => 'domain.status.',
                'Name Server:' => 'domain.nserver.',
                'Nameservers:' => 'domain.nserver.',
                'Maintainer:' => 'domain.referer',

                'Domain Registration Date:' => 'domain.created',
                'Domain Create Date:' => 'domain.created',
                'Domain Expiration Date:' => 'domain.expires',
                'Domain Last Updated Date:' => 'domain.changed',
                'Creation Date:' => 'domain.created',
                'Last Modification Date:' => 'domain.changed',
                'Expiration Date:' => 'domain.expires',
                'Created On:' => 'domain.created',
                'Last Updated On:' => 'domain.changed',

                'Registrant ID:' => 'owner.handle',
                'Registrant Name:' => 'owner.name',
                'Registrant Organization:' => 'owner.organization',
                'Registrant Address:' => 'owner.address.street.',
                'Registrant Address1:' => 'owner.address.street.',
                'Registrant Address2:' => 'owner.address.street.',
                'Registrant Street:' => 'owner.address.street.',
                'Registrant Street1:' => 'owner.address.street.',
                'Registrant Street2:' => 'owner.address.street.',
                'Registrant Street3:' => 'owner.address.street.',
                'Registrant Postal Code:' => 'owner.address.pcode',
                'Registrant City:' => 'owner.address.city',
                'Registrant State/Province:' => 'owner.address.state',
                'Registrant Country:' => 'owner.address.country',
                'Registrant Country/Economy:' => 'owner.address.country',
                'Registrant Phone Number:' => 'owner.phone',
                'Registrant Phone:' => 'owner.phone',
                'Registrant Facsimile Number:' => 'owner.fax',
                'Registrant FAX:' => 'owner.fax',
                'Registrant Email:' => 'owner.email',
                'Registrant E-mail:' => 'owner.email',

                'Administrative Contact ID:' => 'admin.handle',
                'Administrative Contact Name:' => 'admin.name',
                'Administrative Contact Organization:' => 'admin.organization',
                'Administrative Contact Address:' => 'admin.address.street.',
                'Administrative Contact Address1:' => 'admin.address.street.',
                'Administrative Contact Address2:' => 'admin.address.street.',
                'Administrative Contact Postal Code:' => 'admin.address.pcode',
                'Administrative Contact City:' => 'admin.address.city',
                'Administrative Contact State/Province:' => 'admin.address.state',
                'Administrative Contact Country:' => 'admin.address.country',
                'Administrative Contact Phone Number:' => 'admin.phone',
                'Administrative Contact Email:' => 'admin.email',
                'Administrative Contact Facsimile Number:' => 'admin.fax',
                'Administrative Contact Tel:' => 'admin.phone',
                'Administrative Contact Fax:' => 'admin.fax',
                'Administrative ID:' => 'admin.handle',
                'Administrative Name:' => 'admin.name',
                'Administrative Organization:' => 'admin.organization',
                'Administrative Address:' => 'admin.address.street.',
                'Administrative Address1:' => 'admin.address.street.',
                'Administrative Address2:' => 'admin.address.street.',
                'Administrative Postal Code:' => 'admin.address.pcode',
                'Administrative City:' => 'admin.address.city',
                'Administrative State/Province:' => 'admin.address.state',
                'Administrative Country/Economy:' => 'admin.address.country',
                'Administrative Phone:' => 'admin.phone',
                'Administrative E-mail:' => 'admin.email',
                'Administrative Facsimile Number:' => 'admin.fax',
                'Administrative Tel:' => 'admin.phone',
                'Administrative FAX:' => 'admin.fax',
                'Admin ID:' => 'admin.handle',
                'Admin Name:' => 'admin.name',
                'Admin Organization:' => 'admin.organization',
                'Admin Street:' => 'admin.address.street.',
                'Admin Street1:' => 'admin.address.street.',
                'Admin Street2:' => 'admin.address.street.',
                'Admin Street3:' => 'admin.address.street.',
                'Admin Address:' => 'admin.address.street.',
                'Admin Address2:' => 'admin.address.street.',
                'Admin Address3:' => 'admin.address.street.',
                'Admin City:' => 'admin.address.city',
                'Admin State/Province:' => 'admin.address.state',
                'Admin Postal Code:' => 'admin.address.pcode',
                'Admin Country:' => 'admin.address.country',
                'Admin Country/Economy:' => 'admin.address.country',
                'Admin Phone:' => 'admin.phone',
                'Admin FAX:' => 'admin.fax',
                'Admin Email:' => 'admin.email',
                'Admin E-mail:' => 'admin.email',

                'Technical Contact ID:' => 'tech.handle',
                'Technical Contact Name:' => 'tech.name',
                'Technical Contact Organization:' => 'tech.organization',
                'Technical Contact Address:' => 'tech.address.street.',
                'Technical Contact Address1:' => 'tech.address.street.',
                'Technical Contact Address2:' => 'tech.address.street.',
                'Technical Contact Postal Code:' => 'tech.address.pcode',
                'Technical Contact City:' => 'tech.address.city',
                'Technical Contact State/Province:' => 'tech.address.state',
                'Technical Contact Country:' => 'tech.address.country',
                'Technical Contact Phone Number:' => 'tech.phone',
                'Technical Contact Facsimile Number:' => 'tech.fax',
                'Technical Contact Phone:' => 'tech.phone',
                'Technical Contact Fax:' => 'tech.fax',
                'Technical Contact Email:' => 'tech.email',
                'Technical ID:' => 'tech.handle',
                'Technical Name:' => 'tech.name',
                'Technical Organization:' => 'tech.organization',
                'Technical Address:' => 'tech.address.street.',
                'Technical Address1:' => 'tech.address.street.',
                'Technical Address2:' => 'tech.address.street.',
                'Technical Postal Code:' => 'tech.address.pcode',
                'Technical City:' => 'tech.address.city',
                'Technical State/Province:' => 'tech.address.state',
                'Technical Country/Economy:' => 'tech.address.country',
                'Technical Phone Number:' => 'tech.phone',
                'Technical Facsimile Number:' => 'tech.fax',
                'Technical Phone:' => 'tech.phone',
                'Technical Fax:' => 'tech.fax',
                'Technical FAX:' => 'tech.fax',
                'Technical E-mail:' => 'tech.email',
                'Tech ID:' => 'tech.handle',
                'Tech Name:' => 'tech.name',
                'Tech Organization:' => 'tech.organization',
                'Tech Address:' => 'tech.address.street.',
                'Tech Address2:' => 'tech.address.street.',
                'Tech Address3:' => 'tech.address.street.',
                'Tech Street:' => 'tech.address.street.',
                'Tech Street1:' => 'tech.address.street.',
                'Tech Street2:' => 'tech.address.street.',
                'Tech Street3:' => 'tech.address.street.',
                'Tech City:' => 'tech.address.city',
                'Tech Postal Code:' => 'tech.address.pcode',
                'Tech State/Province:' => 'tech.address.state',
                'Tech Country:' => 'tech.address.country',
                'Tech Country/Economy:' => 'tech.address.country',
                'Tech Phone:' => 'tech.phone',
                'Tech FAX:' => 'tech.fax',
                'Tech Email:' => 'tech.email',
                'Tech E-mail:' => 'tech.email',

                'Billing Contact ID:' => 'billing.handle',
                'Billing Contact Name:' => 'billing.name',
                'Billing Contact Organization:' => 'billing.organization',
                'Billing Contact Address1:' => 'billing.address.street.',
                'Billing Contact Address2:' => 'billing.address.street.',
                'Billing Contact Postal Code:' => 'billing.address.pcode',
                'Billing Contact City:' => 'billing.address.city',
                'Billing Contact State/Province:' => 'billing.address.state',
                'Billing Contact Country:' => 'billing.address.country',
                'Billing Contact Phone Number:' => 'billing.phone',
                'Billing Contact Facsimile Number:' => 'billing.fax',
                'Billing Contact Email:' => 'billing.email',
                'Billing ID:' => 'billing.handle',
                'Billing Name:' => 'billing.name',
                'Billing Organization:' => 'billing.organization',
                'Billing Address:' => 'billing.address.street.',
                'Billing Address1:' => 'billing.address.street.',
                'Billing Address2:' => 'billing.address.street.',
                'Billing Address3:' => 'billing.address.street.',
                'Billing Street:' => 'billing.address.street.',
                'Billing Street1:' => 'billing.address.street.',
                'Billing Street2:' => 'billing.address.street.',
                'Billing Street3:' => 'billing.address.street.',
                'Billing City:' => 'billing.address.city',
                'Billing Postal Code:' => 'billing.address.pcode',
                'Billing State/Province:' => 'billing.address.state',
                'Billing Country:' => 'billing.address.country',
                'Billing Country/Economy:' => 'billing.address.country',
                'Billing Phone:' => 'billing.phone',
                'Billing Fax:' => 'billing.fax',
                'Billing FAX:' => 'billing.fax',
                'Billing Email:' => 'billing.email',
                'Billing E-mail:' => 'billing.email',

                'Zone ID:' => 'zone.handle',
                'Zone Organization:' => 'zone.organization',
                'Zone Name:' => 'zone.name',
                'Zone Address:' => 'zone.address.street.',
                'Zone Address 2:' => 'zone.address.street.',
                'Zone City:' => 'zone.address.city',
                'Zone State/Province:' => 'zone.address.state',
                'Zone Postal Code:' => 'zone.address.pcode',
                'Zone Country:' => 'zone.address.country',
                'Zone Phone Number:' => 'zone.phone',
                'Zone Fax Number:' => 'zone.fax',
                'Zone Email:' => 'zone.email',
            ];
        }

        $r = [];
        $disok = true;

        foreach ($rawData as $val) {
            if ('' !== \trim($val)) {
                if ($disok && ('%' === $val[0] || '#' === $val[0])) {
                    $r['disclaimer'][] = \trim(\substr($val, 1));
                    $disok = true;

                    continue;
                }

                $disok = false;

                foreach ($items as $match => $field) {
                    $pos = \strpos($val, $match);

                    if (false !== $pos) {
                        if ('' != $field) {
                            $itm = \trim(\substr($val, $pos + \strlen($match)));

                            if ('' != $itm) {
                                ${'r'.self::getVarName($field)} = '="'.\str_replace('"', '\"', $itm).'";';
                            }
                        }

                        if (!$scanAll) {
                            break;
                        }
                    }
                }
            }
        }

        if (empty($r)) {
            if ($hasReg) {
                $r['registered'] = 'no';
            }
        } else {
            if ($hasReg) {
                $r['registered'] = 'yes';
            }

            $r = self::format_dates($r, $dateFormat);
        }

        return $r;
    }

    private static function getVarName(string $vdef): string
    {
        $parts = \explode('.', $vdef);
        $var = '';

        foreach ($parts as $mn) {
            if ('' === $mn) {
                $var .= '[]';
            } else {
                $var .= '["'.$mn.'"]';
            }
        }

        return $var;
    }

    public static function get_blocks(array $rawData, array $items, bool $partialMatch = false, bool $defBlock = false): array
    {
        $r = [];
        $endTag = '';
        $processedKey = -1;

        foreach ($rawData as $keyBlock => $valBlock) {
            if ($processedKey >= $keyBlock) {
                continue;
            }
            $processedKey = $keyBlock;

            $valBlock = \trim($valBlock);
            if ('' === $valBlock) {
                continue;
            }

            $var = $found = false;

            foreach ($items as $field => $match) {
                $pos = \strpos($valBlock, $match);

                if ('' != $field && false !== $pos) {
                    if ($valBlock == $match) {
                        $found = true;
                        $endTag = '';
                        $line = $valBlock;

                        break;
                    }

                    $last = $valBlock[\strlen($valBlock) - 1];

                    if (':' === $last || '-' === $last || ']' === $last) {
                        $found = true;
                        $endTag = $last;
                        $line = $valBlock;
                    } else {
                        $var = self::getVarName(\strtok($field, '#'));
                        $itm = \trim(\substr($valBlock, $pos + \strlen($match)));

                        ${'r'.$var} = $itm;
                    }

                    break;
                }
            }

            if (!$found) {
                if (!$var && $defBlock) {
                    $r[$defBlock][] = $valBlock;
                }

                continue;
            }

            $block = [];

            // Block found, get data ...

            foreach ($rawData as $keyData => $valData) {
                if ($processedKey >= $keyData) {
                    continue;
                }
                $processedKey = $keyData;

                $valData = \trim($valData);

                if ('' === $valData || $valData === \str_repeat($valData[0], \strlen($valData))) {
                    continue;
                }

                $last = $valData[\strlen($valData) - 1];
                if ('' === $endTag || $partialMatch || $last === $endTag) {
                    // Check if this line starts another block
                    $et = false;

                    foreach ($items as $match) {
                        $pos = \strpos($valData, $match);

                        if (false !== $pos && 0 === $pos) {
                            $et = true;

                            break;
                        }
                    }

                    if ($et) {
                        // Another block found
                        --$processedKey;

                        break;
                    }
                }

                $block[] = $valData;
            }

            if (empty($block)) {
                continue;
            }

            foreach ($items as $field => $match) {
                $pos = \strpos($line, $match);

                if (false !== $pos) {
                    $var = self::getVarName(\strtok($field, '#'));
                    if ('[]' !== $var) {
                        ${'r'.$var} = $block;
                    }
                }
            }
        }

        return $r;
    }

    public static function easy_parser(
        array $data_raw,
        array $items,
        string $date_format,
        array $translate = [],
        bool $has_org = false,
        bool $partial_match = false,
        bool $def_block = false
    ) {
        $r = self::get_blocks($data_raw, $items, $partial_match, $def_block);
        $r = self::get_contacts($r, $translate, $has_org);

        return self::format_dates($r, $date_format);
    }

    public static function get_contacts(array $array, array $extra_items = [], bool $has_org = false): array
    {
        if (isset($array['billing'])) {
            $array['billing'] = self::get_contact($array['billing'], $extra_items, $has_org);
        }

        if (isset($array['tech'])) {
            $array['tech'] = self::get_contact($array['tech'], $extra_items, $has_org);
        }

        if (isset($array['zone'])) {
            $array['zone'] = self::get_contact($array['zone'], $extra_items, $has_org);
        }

        if (isset($array['admin'])) {
            $array['admin'] = self::get_contact($array['admin'], $extra_items, $has_org);
        }

        if (isset($array['owner'])) {
            $array['owner'] = self::get_contact($array['owner'], $extra_items, $has_org);
        }

        if (isset($array['registrar'])) {
            $array['registrar'] = self::get_contact($array['registrar'], $extra_items, $has_org);
        }

        return $array;
    }

    public static function get_contact(array $array, array $extra_items = [], bool $has_org = false): array
    {
        if (!$array) {
            return [];
        }

        $items = [
            'fax..:' => 'fax',
            'fax.' => 'fax',
            'fax-no:' => 'fax',
            'fax -' => 'fax',
            'fax-' => 'fax',
            'fax::' => 'fax',
            'fax:' => 'fax',
            '[fax]' => 'fax',
            '(fax)' => 'fax',
            'fax' => 'fax',
            'tel. ' => 'phone',
            'tel:' => 'phone',
            'phone::' => 'phone',
            'phone:' => 'phone',
            'phone-' => 'phone',
            'phone -' => 'phone',
            'email:' => 'email',
            'e-mail:' => 'email',
            'company name:' => 'organization',
            'organisation:' => 'organization',
            'first name:' => 'name.first',
            'last name:' => 'name.last',
            'street:' => 'address.street',
            'address:' => 'address.street.',
            'language:' => '',
            'location:' => 'address.city',
            'country:' => 'address.country',
            'name:' => 'name',
            'last modified:' => 'changed',
        ];

        if ($extra_items) {
            foreach ($items as $match => $field) {
                if (!isset($extra_items[$match])) {
                    $extra_items[$match] = $field;
                }
            }
            $items = $extra_items;
        }

        foreach ($array as $key => $val) {
            $ok = true;

            while ($ok) {
                $ok = false;

                foreach ($items as $match => $field) {
                    $pos = \stripos($val, $match);

                    if (false === $pos) {
                        continue;
                    }

                    $itm = \trim(\substr($val, $pos + \strlen($match)));

                    if ('' != $field && '' !== $itm) {
                        ${'r'.self::getVarName($field)} = $itm;
                    }

                    $val = \trim(\substr($val, 0, $pos));

                    if ('' === $val) {
                        unset($array[$key]);

                        break;
                    }
                    $array[$key] = $val;
                    $ok = true;

                    // break;
                }

                if (\preg_match('/([+]*[-\\(\\)\\. x0-9]){7,}/', $val, $matches)) {
                    $phone = \trim(\str_replace(' ', '', $matches[0]));

                    if (\strlen($phone) > 8 && !\preg_match('/[0-9]{5}\-[0-9]{3}/', $phone)) {
                        if (isset($r['phone'])) {
                            if (isset($r['fax'])) {
                                continue;
                            }
                            $r['fax'] = \trim($matches[0]);
                        } else {
                            $r['phone'] = \trim($matches[0]);
                        }

                        $val = \str_replace($matches[0], '', $val);

                        if ('' === $val) {
                            unset($array[$key]);

                            continue;
                        }
                        $array[$key] = $val;
                        $ok = true;
                    }
                }

                if (\preg_match('/([-0-9a-zA-Z._+&\/=]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,6})/', $val, $matches)) {
                    $r['email'] = $matches[0];

                    $val = \str_replace($matches[0], '', $val);
                    $val = \trim(\str_replace('()', '', $val));

                    if ('' === $val) {
                        unset($array[$key]);

                        continue;
                    }
                    if (!isset($r['name'])) {
                        $r['name'] = $val;
                        unset($array[$key]);
                    } else {
                        $array[$key] = $val;
                    }

                    $ok = true;
                }
            }
        }

        if (!isset($r['name']) && \count($array) > 0) {
            $r['name'] = \array_shift($array);
        }

        if ($has_org && \count($array) > 0) {
            $r['organization'] = \array_shift($array);
        }

        if (isset($r['name']) && \is_array($r['name'])) {
            $r['name'] = \implode(' ', $r['name']);
        }

        if (!empty($array)) {
            if (isset($r['address'])) {
                $r['address'] = \array_merge($r['address'], $array);
            } else {
                $r['address'] = $array;
            }
        }

        return $r;
    }

    public static function format_dates(array $res, string $format = 'mdy'): array
    {
        if (!$res) {
            return $res;
        }

        foreach ($res as $key => $val) {
            if (\is_array($val)) {
                if (!\is_numeric($key) && ('expires' === $key || 'created' === $key || 'changed' === $key)) {
                    $d = self::get_date($val[0], $format);
                    if ($d) {
                        $res[$key] = $d;
                    }
                } else {
                    $res[$key] = self::format_dates($val, $format);
                }
            } else {
                if (!\is_numeric($key) && ('expires' === $key || 'created' === $key || 'changed' === $key)) {
                    $d = self::get_date($val, $format);
                    if ($d) {
                        $res[$key] = $d;
                    }
                }
            }
        }

        return $res;
    }

    public static function get_date(string $date, string $format): string
    {
        $strToTime = \strtotime($date);
        if ($strToTime > 0) {
            return \date('Y-m-d', $strToTime);
        }

        $months = [
            'jan' => 1,
            'ene' => 1,
            'feb' => 2,
            'mar' => 3,
            'apr' => 4,
            'abr' => 4,
            'may' => 5,
            'jun' => 6,
            'jul' => 7,
            'aug' => 8,
            'ago' => 8,
            'sep' => 9,
            'oct' => 10,
            'nov' => 11,
            'dec' => 12,
            'dic' => 12,
        ];

        $parts = \explode(' ', $date);

        if (\str_contains($parts[0], '@')) {
            unset($parts[0]);
            $date = \implode(' ', $parts);
        }

        $date = \str_replace(',', ' ', \trim($date));
        $date = \str_replace('.', ' ', $date);
        $date = \str_replace('-', ' ', $date);
        $date = \str_replace('/', ' ', $date);
        $date = \str_replace("\t", ' ', $date);

        $parts = \explode(' ', $date);
        $res = [];

        if ((8 === \strlen($parts[0]) || 1 === \count($parts)) && \is_numeric($parts[0])) {
            $val = $parts[0];
            for ($p = $i = 0; $i < 3; ++$i) {
                if ('Y' !== $format[$i]) {
                    $res[$format[$i]] = \substr($val, $p, 2);
                    $p += 2;
                } else {
                    $res['y'] = \substr($val, $p, 4);
                    $p += 4;
                }
            }
        } else {
            $format = \strtolower($format);

            for ($p = $i = 0; $p < \count($parts) && $i < \strlen($format); ++$p) {
                if ('' === \trim($parts[$p])) {
                    continue;
                }

                if ('-' !== $format[$i]) {
                    $res[$format[$i]] = $parts[$p];
                }
                ++$i;
            }
        }

        if (!$res) {
            return $date;
        }

        $ok = false;

        while (!$ok) {
            $ok = true;

            foreach ($res as $key => $val) {
                if ('' == $val || '' == $key) {
                    continue;
                }

                if (!\is_numeric($val) && isset($months[\strtolower(\substr($val, 0, 3))])) {
                    $res[$key] = $res['m'];
                    $res['m'] = $months[\strtolower(\substr($val, 0, 3))];
                    $ok = false;

                    break;
                }

                if ('y' !== $key && 'Y' !== $key && $val > 1900) {
                    $res[$key] = $res['y'];
                    $res['y'] = $val;
                    $ok = false;

                    break;
                }
            }
        }

        if ($res['m'] > 12) {
            $v = $res['m'];
            $res['m'] = $res['d'];
            $res['d'] = $v;
        }

        if ($res['y'] < 70) {
            $res['y'] += 2000;
        } elseif ($res['y'] <= 99) {
            $res['y'] += 1900;
        }

        return \sprintf('%.4d-%02d-%02d', $res['y'], $res['m'], $res['d']);
    }
}
