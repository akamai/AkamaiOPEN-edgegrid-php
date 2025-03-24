<?php
include 'akamai-open-edgegrid-auth.phar';
$auth = \Akamai\Open\EdgeGrid\Authentication::createFromEdgeRcFile('default', './tests/edgerc/.edgerc');
var_dump($auth);
