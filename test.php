<?php
header("Content-Type: text/html;charset=UTF-8");

$t1 = microtime(true);
require 'PDO.php';

$pdo = new PDO('mysql:host=127.0.0.1;dbname=test', 'root', '');
$result = $pdo->query("SELECT * FROM user LIMIT 20", PDO::FETCH_ASSOC);
foreach($result as $row)
{
	print_r($row);
}
$t2 = microtime(true);
echo "\n耗时" . round($t2 - $t1, 3) . '秒';
