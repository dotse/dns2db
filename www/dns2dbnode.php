<?php

$qtype = array();
$qtype['1']='A';
$qtype['2']='NS';
$qtype['3']='MD';
$qtype['4']='MF';
$qtype['5']='CNAME';
$qtype['6']='SOA';
$qtype['7']='MB';
$qtype['8']='MG';
$qtype['9']='MR';
$qtype['10']='NULL';
$qtype['11']='WKS';
$qtype['12']='PTR';
$qtype['13']='HINFO';
$qtype['14']='MINFO';
$qtype['15']='MX';
$qtype['16']='TXT';
$qtype['17']='RP';
$qtype['18']='AFSDB';
$qtype['19']='X25';
$qtype['20']='ISDN';
$qtype['21']='RT';
$qtype['22']='NSAP';
$qtype['23']='NSAP-PTR';
$qtype['24']='SIG';
$qtype['25']='KEY';
$qtype['26']='PX';
$qtype['27']='GPOS';
$qtype['28']='AAAA';
$qtype['29']='LOC';
$qtype['30']='NXT';
$qtype['31']='EID';
$qtype['32']='NIMLOC';
$qtype['33']='SRV';
$qtype['34']='ATMA';
$qtype['35']='NAPTR';
$qtype['36']='KX';
$qtype['37']='CERT';
$qtype['38']='A6';
$qtype['39']='DNAME';
$qtype['40']='SINK';
$qtype['41']='OPT';
$qtype['42']='APL';
$qtype['43']='DS';
$qtype['44']='SSHFP';
$qtype['45']='IPSECKEY';
$qtype['46']='RRSIG';
$qtype['47']='NSEC';
$qtype['48']='DNSKEY';
$qtype['49']='DHCID';
$qtype['99']='SPF';
$qtype['100']='UINFO';
$qtype['101']='UID';
$qtype['102']='GID';
$qtype['103']='UNSPEC';
$qtype['249']='TKEY';
$qtype['250']='TSIG';
$qtype['251']='IXFR';
$qtype['252']='AXFR';
$qtype['253']='MAILB';
$qtype['254']='MAILA';
$qtype['255']='*';
$qtype['32768']='TA';
$qtype['32769']='DLV';

$qclass = array();
$qclass['1']='IN';
$qclass['3']='Chaos';
$qclass['4']='Hesiod';
$qclass['254']='None';
$qclass['255']='Any';

$s = 0;

$day='';
$time='';
$count=5;
if (isset($_GET['day']))
	$day = $_GET['day'];
if (isset($_GET['time']))
	$time = $_GET['time'];
if (isset($_GET['count']))
	$count = $_GET['count'];
$limit = " limit ".$count;

if (!file_exists("dns2dbnode_conf.php"))
{
    error_log("[dns2db] copy dns2dbnode_conf.php.example to dns2dbnode_conf.php and check it's configuration");
    exit();
}
        

include('dns2dbnode_conf.php');
header("content-type: text/xml");

// Change the DNS2DB path below to the path of your db-files.
$dsn = "sqlite:".$database;
$dbh = false;
try
{
	if ( file_exists( $database ) )
	{
		$dbh = new PDO($dsn);
	}
}
catch(Exception $e)
{
	$err = "Error opening database (".$database.") ".$e->getMessage();
	error_log($err);
    echo "  <error>\n";
    echo "    cannot open database\n";
    echo "  </error>\n";
 	exit();
}

if ($dbh == false)
{
    echo "  <error>\n";
    echo "    no database\n";
    echo "  </error>\n";
 	exit();
}


if (!isset($_GET['function'])) {

	echo "Error: no function !\n";
	exit(0);

}else if ($_GET['function'] == 'topdomains') {

	$stmt = $dbh->prepare("select count (*)/5 qcount, trim (rr_lvl2dom || rr_lvl1dom, '.') from q group by rr_lvl2dom, rr_lvl1dom order by qcount desc".$limit);
	$stmt->execute();

}else if ($_GET['function'] == 'topresolvers') {

 	$stmt = $dbh->prepare("select count (*)/5 as qcount, src_addr from q group by src_addr order by qcount desc".$limit);
        $stmt->execute();

}else if ($_GET['function'] == 'toprrtypes') {

 	$stmt = $dbh->prepare("select count(*) as qcount ,rr_type from q group by rr_type order by qcount desc;");
        $stmt->execute();

}else if ($_GET['function'] == 'resolversfordomain') {

	$stmt = $dbh->prepare("select count(id)/5 as qcount, src_addr as domain from q where trim (rr_lvl2dom || rr_lvl1dom, '.') = \"". 
$_GET['domain'] ."\" group by domain order by qcount desc".$limit);
        $stmt->execute();

}else if ($_GET['function'] == 'domainforresolver') {

	$stmt = $dbh->prepare("select count (*)/5 as qcount,
	   trim (rr_lvl2dom || rr_lvl1dom, '.') as domain,
	   trim(rr_cname, '.') as domain,
	   rr_type as qtype,
	   rr_class as qclass
	from q where src_addr =  \"".$_GET['resolver']."\"
	group by domain, rr_type
	order by qcount desc".$limit);
    $stmt->execute();
    $s = 1;

} else {

	echo "Error: no valid function (".$_GET['function'].")!\n";
	exit(0);
}


echo "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n";
echo "<items>\n";
//echo "  <time>".date("Y-m-d H:i")."</time>\n";

$i = 0;
while ($row = $stmt->fetch()) {
    $i+=1;

    $dom="";
    if ($s == 1) {
      $dom = $row[2]." (".$qclass[$row[4]]." ".$qtype[$row[3]].")";
    } else {
      $dom = $row[1];
    }

    echo "  <item>\n";
    echo "    <position>".$i."</position>\n";
    echo "    <qcount>".$row[0]."</qcount>\n";
    echo "    <domain>".$row[1]."</domain>\n";
    echo "    <displaytext>".$dom."</displaytext>\n";
    echo "  </item>\n";
}
echo "</items>\n";
?>
