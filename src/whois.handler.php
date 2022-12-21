<?php

abstract class WhoisHandler
{
    abstract public function parse(WhoisClient $whoisClient, array $data_str, $query): ?array;
}
