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

// Change the DNS2DB path below to the path of your db-files.
$dsn = "sqlite:/DNS2DB/".$_GET['day']."/Fq.".$_GET['day']."_".$_GET['time'].".db";
$dbh = new PDO($dsn);

$dsn = "sqlite:reversedb.db3";
$rev = new PDO($dsn);
$lookup = $rev->prepare("select name from revdb where ip = ?");
$add = $rev->prepare("insert into revdb (ip, name) values (?, ?)");

if ($_GET['search'] == 'null') {
    $stmt = $dbh->prepare("select count(id)/5 as qcount, E1 as domain from q group by E1 order by qcount desc limit ".$_GET['count']);
    $stmt->execute();
} else if ($_GET['search'] == '--topservers--') {
    $stmt = $dbh->prepare("select count(id)/5 as qcount, Client as domain from q group by Client order by qcount desc limit ".$_GET['count']);
    $stmt->execute();
    $s = 2;
} else if ($_GET['server'] == 'false') {
    $stmt = $dbh->prepare("select count(id)/5 as qcount, Client as domain from q where E1 = \"". $_GET['search'] ."\" group by domain order by qcount desc limit ".$_GET['count']);
    $stmt->execute();
    $s = 2;
} else {
    $stmt = $dbh->prepare("select count(id)/5 as qcount, E1 as domain, Qname as domain, Qtype, Qclass from q where Client = \"". $_GET['search'] ."\" group by domain, qtype order by qcount desc limit ".$_GET['count']);
    // print_r($dbh->errorInfo());
   // echo "select count(id)/5 as qcount, E1 as domain, Qname as domain, Qtype, Qclass from q where Client = \"". $_GET['search'] ."\" group by domain, qtype order by qcount desc limit ".$_GET['count'];
    $stmt->execute();
    $s = 1;
}

header("content-type: text/xml");

echo "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n";
echo "<items>\n";
//echo "  <time>".date("Y-m-d H:i")."</time>\n";

$i = 0;
while ($row = $stmt->fetch()) {
    $i+=1;

    if ($s == 1) {
      $dom = $row[2]." (".$qclass[$row[4]]." ".$qtype[$row[3]].")";
    } else if ($s == 2) {
      $lookup->execute(array($row[1]));
      $dom = $lookup->fetchcolumn();
      if ($dom == "") {
        $dom = gethostbyaddr($row[1]);
        $add->execute(array($row[1], $dom));
//	$dom = "(NEW)-".$dom;
      }
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
