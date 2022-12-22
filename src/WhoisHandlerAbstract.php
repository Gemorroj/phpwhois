<?php

abstract class WhoisHandlerAbstract
{
    abstract public function parse(Whois $whoisClient, array $data_str, $query): ?array;
}
