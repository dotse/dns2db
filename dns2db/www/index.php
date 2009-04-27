<html lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Trafficanalysis</title>
<style>
body { margin: 0px; overflow:hidden }
</style>
</head>

<body scroll="no">
<?php
$bgcolor ="0xa0a0a0";
$application= "dns2db";

if (!file_exists("dns2db_conf.php"))
{
    error_log("[dns2db] copy dns2db_conf.php.example to dns2db_conf.php and check it's configuration");
?>

Error dns2db is not configured. Check the webserver error log for more information.

</body>
</html>
<?php
    exit();
}
        
include ('dns2db_conf.php');
?>
  	<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000"
			id="<?php echo $application ?>" width="1280" height="1024"
			codebase="https://fpdownload.macromedia.com/get/flashplayer/current/swflash.cab">
			<param name="movie" value="<?php echo $swf; ?>" />
			<param name="quality" value="high" />
			<param name="bgcolor" value="<?php echo $bgcolor; ?>" />
			<param name="allowScriptAccess" value="sameDomain" />
			<param name='flashvars' value='url=<?php echo $url; ?>'/>
			<embed src="<?php echo $swf; ?>" quality="high" bgcolor="<?php echo $bgcolor; ?>"
				width="100%" height="100%" name="<?php echo $application; ?>" align="middle"
				play="true"
				loop="false"
				quality="high"
				allowScriptAccess="sameDomain"
				flashvars="url=<?php echo $url ;?>"
				type="application/x-shockwave-flash"
				pluginspage="http://www.adobe.com/go/getflashplayer">
			</embed>
	</object>
</body>
</html>
