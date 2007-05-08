<?

header("content-type: text/xml");
$fp = fopen("http://****SERVER****/trafficstat.api.php?".$_SERVER['QUERY_STRING'], 'r');
fpassthru($fp);

?>

