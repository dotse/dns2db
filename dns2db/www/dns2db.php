<?php

if (!file_exists("dns2db_conf.php"))
{
    error_log("[dns2db] copy dns2db_conf.php.example to dns2db_conf.php and check it's configuration");
    exit();
}

include ('dns2db_conf.php');

  
header("content-type: text/xml");
//header("content-type: text/plain");

echo "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n";

# make default nodestring if not set
if (!isset($_GET['nodes']))
{
    $nodestr="";
    $sep="";
    foreach ($nodes as $i) {
	$nodestr.=$sep.$i['name'];
	$sep=",";
    }
}
else
{
    $nodestr=$_GET['nodes'];
}


# decode nodestring into $nodearray

$nodeent = split(',',$nodestr);
$nodearray = array();
foreach ($nodeent as $i)
{
    foreach ($nodes as &$j) {
	if ($i== $j['name'] && !isset($j['found']) ) {
	    $j['found']=1;    
            array_push($nodearray , $j);
        }
    }
}


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


###################### dns lookup class with cache sqlite db (see $dsn at the top of the file ) ##################3
class Lookup
{
    public $rev;
    public $lookup;
    public $add;
    public $error;

    function __construct()
    {
    	$error = false;
	    global $database;
		$dsn = "sqlite:".$database;

        try 
        {
	        $this->rev = new PDO($dsn);
        } 
        catch (PDOException $e) 
        {
            error_log ('[dns2db] Connection to reverse lookup database ('.$database.') failed, check dns2db_conf.php: ' . $e->getMessage());
		  	$this->error = true;
        }
        
        if (!$this->error)
        {
	    	$this->rev->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_WARNING );
        	$this->lookup = $this->rev->prepare("select name from revdb where ip = ?");
        	$this->add = $this->rev->prepare("insert into revdb (ip, name) values (?, ?)");
        }
    }

    function incache($rev)
    {
    	if ($this->error == true)
    		return "";
        $this->lookup->execute(array($rev));
        $dom = $this->lookup->fetchcolumn();
        return $dom;
    }
    function lookup($rev)
    {
        $dom = $this->incache($rev);
        if ($dom == "") {
            $dom = gethostbyaddr($rev);
        	if (!$this->error)
        	{
            	$this->add->execute(array($rev, $dom));
            }
        }
        return $dom;
    }
}


$lookup = new Lookup();



function getnoderesult($nodeurl)
{
    $sep ='?';
    $params ="";
    $valid=array('function','day','time','count','resolver','domain');
    foreach($valid as $i) {
	    if (isset($_GET[$i]))
        {
	        $val = $_GET[$i];
	        if ($i == 'count')
		        $val=$val*4;
	        $params.=$sep.$i."=".$val;
    	    $sep ='&';
	    }
    }

    $xml = new SimpleXMLElement(file_get_contents($nodeurl.$params, 'r'));

    return $xml;
}


#print_r ($_GET);
$count=0;
if (isset($_GET['count']))
    $count = $_GET['count'];


if (!isset($_GET['function'])) {

	echo "Error: no function !\n";
	exit(0);

}else if ($_GET['function'] == 'lookup') {
        $dom = $lookup->lookup($_GET['lookup']);
        echo "<lookup ip=\"".$_GET['lookup']."\" name=\"".$dom."\"/>";
        exit();

}else if ($_GET['function'] == 'nodelist') {
    echo "<items>\n";
    foreach($nodes as $i)
    {
        echo "  <server name=\"".$i['name']."\" dnsname=\"".$i['dnsname']."\" displayname=\"".$i['displayname']."\" description=\"".$i['description']."\" />\n";
    }
    echo "</items>\n";
    exit(0);

}else if ($_GET['function'] == 'filterlist') {
?>
<items>
  <filter name="tcp" code="T" default="1"/>
  <filter name="udp" code="U" default="1"/>
  <filter name="v4" code="4" default="1"/>
  <filter name="v6" code="6" default="1"/>
  <filter name="qtype" code="QT" default="ALL" opts="ALL,<?php
  foreach($qtype as $type)
  {
     echo "$type,";
  }
  ?>"/>
</items>
<?php
    exit(0);

}else if ($_GET['function'] == 'rrstats') {
    echo "<items>\n";
    foreach($rrstats as $i)
    {
        echo "  <rrtype name=\"".$i['name']."\" percent=\"".$i['percent']."\" deviation=\"".$i['deviation']."\" />\n";
    }
    echo "</items>\n";
    exit(0);

}else if ($_GET['function'] == 'toprrtypes') {
	$count = 500;
	$s=3;
}else if ($_GET['function'] == 'topdomains') {

}else if ($_GET['function'] == 'topresolveranddomain') {

}else if ($_GET['function'] == 'topresolvers') {
        $s = 2;

}else if ($_GET['function'] == 'resolversfordomain') {
        $s = 2;

}else if ($_GET['function'] == 'domainforresolver') {
    	$s = 1;

} else {
	echo "Error: no valid function (".$_GET['function'].")!\n";
	exit(0);
}

##############  create an sqlite memory db

if ($db = new PDO('sqlite::memory:')) 
{ 
    $stmt = $db->prepare( 'CREATE TABLE q (domain text,qcount int,displaytext text)');
    $stmt->execute();
    $insert = $db->prepare( "INSERT INTO q VALUES(?,?,?)");
    $sel = $db->prepare( "select sum(qcount) as qcount,domain,displaytext from q group by domain order by qcount desc limit ".$count);
} else {
    die($sqliteerror);
}



############### create param string
$sep ='?';
$params ="";
$valid=array('function','day','time','count','resolver','domain','filters');
foreach($valid as $i) {
    if (isset($_GET[$i]))
    {
        $val = $_GET[$i];
	if ($i == 'count')
	    $val=$val*4;
	$params.=$sep.$i."=".$val;
    	$sep ='&';
    }
}


##############  use multi curl to get result from all servers
$cha = array();
$success = array();
$count = 0;
foreach($nodearray as $i) {
    $ch = curl_init();
    $success[$count] = "0";
    $cha[$count++] = $ch;
    curl_setopt($ch,CURLOPT_URL,$i['url'].$params);
    curl_setopt($ch,CURLOPT_USERPWD,$i['cred']);
    curl_setopt($ch,CURLOPT_HTTPAUTH,CURLAUTH_ANY);
    curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,false);
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,TRUE);
    curl_setopt($ch,CURLOPT_HEADER,0);
}

$mh = curl_multi_init();

foreach($cha as $ch) {
    curl_multi_add_handle($mh,$ch);
}

$active = null;

//execute the handles
do {
    $mrc = curl_multi_exec($mh, $active);
} while ($mrc == CURLM_CALL_MULTI_PERFORM);

while ($active && $mrc == CURLM_OK) {
    if (curl_multi_select($mh) != -1) {
        do {
            $mrc = curl_multi_exec($mh, $active);
        } while ($mrc == CURLM_CALL_MULTI_PERFORM);
    }
}
$res = Array();
$count = 0;
//close the handles
foreach($cha as $ch) {
    $res[$count++] = curl_multi_getcontent($ch);
    curl_multi_remove_handle($mh, $ch);
}
curl_multi_close($mh);

# grab all results
$counter = 0;
foreach($res as $xmlstring) {
    try
    {
    	$xml = new SimpleXMLElement($xmlstring);

    	foreach ($xml as $item)
    	{
    	    $success[$counter]="1";
	        $dom =   $item->domain;
	        $count = $item->qcount;
	        $disp =  $item->displaytext;

            $insert->execute(array($dom,$count,$disp));
    	}
    }
    catch (Exception $e)
    {
    }
    $counter++;
}


$sel->execute(); 

echo "<items>\n";
$i = 0;
while ($row = $sel->fetch()) {
    $i+=1;

    $dom="";
    if ($s == 1) {
        $dom = $row[2]." (".$qclass[$row[4]]." ".$qtype[$row[3]].")";
    } else if ($s == 2) {
        $dom = $lookup->incache($row[1]);
        if ($dom=="")
            $dom=$row[1];
    } else if ($s == 3) {
        $dom=$row[1];
        if (isset($qtype[$row[1]]))
            $dom = $qtype[$row[1]];
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
$count = 0;
echo "  <status>\n";
foreach($success as $res) {
    echo "    <node name=\"".$nodearray[$count]['name']."\" result=\"$res\" />\n";
    $count++;
}
echo "  </status>\n";

echo "</items>\n";
?>
