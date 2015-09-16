<?
 //error_reporting(-1);
 //ini_set('display_errors',1);
 //ini_set('display_startup_errors',1);
 error_reporting (E_ERROR | E_WARNING | E_PARSE); // This will NOT report uninitialized variables
 // Turnoff all error reporting
 //error_reporting(0);
 //ini_set('display_errors', 0);
 //ini_set('log_errors', 0);

 require('config.php');

 printf("<BR><BR>=== CRYPTSECURE SETUP ====<BR><BR>");


 function opendb() {
     global $WEBMASTER;
     global $DBUSER;
     global $DBPWD;
     global $DBURL;
     $dbs = @mysql_connect($DBURL,$DBUSER,$DBPWD);
     if(!$dbs) { echo '-CANNOT ACCESS DATABASESERVER, PLEASE CONTACT THE SYSTEM ADMINISTARTOR AT '.$WEBMASTER; exit;}
     return $dbs;
 }

 $connection = opendb();
 $db = 0;
 if ($connection) $db =  mysql_select_db($DBNAME,$connection);
 if($db) {
 	  echo '-SETUP HAS ALREADY RUN, PLEASE CONTACT THE SYSTEM ADMINISTARTOR AT '.$WEBMASTER;
 	  exit;
 }

 // Create database
 $sql = "CREATE DATABASE ".$DBNAME;
 echo "Creating Database... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}
 //$success = mysql_query($sql);


 if ($connection) $db =  mysql_select_db($DBNAME,$connection);
 if(!$db) {
     echo "Error creating database. Is the db already created? Has user '".$DBUSER."' enough rights to create a DB? Is the password correct?";
 	  exit;
 } else {
     echo "Database created successfully.<BR>";
 }


     echo "<BR><BR>Now creating tables...<BR><BR>";


$sql = 'CREATE TABLE IF NOT EXISTS `users` ('
        . ' `uid` INT NOT NULL AUTO_INCREMENT, '
        . ' `username` VARCHAR(20) NOT NULL, '
        . ' `email` VARCHAR(50) NOT NULL, '
        . ' `pwd` VARCHAR(50) NOT NULL, '
        . ' `registered` VARCHAR(50) NOT NULL, '
        . ' `alive` VARCHAR(50) NOT NULL, '
        . ' `active` INT NOT NULL, '
        . ' `pwdchange` VARCHAR(50) NOT NULL,'
        . ' `activation` VARCHAR(50) NOT NULL, '
        . ' `phone` VARCHAR(2000) NOT NULL, '
        . ' `avatar` VARCHAR(20000) NOT NULL, '
        . ' `pwderr` INT NOT NULL default 0, '
        . ' PRIMARY KEY (`uid`)'
        . ' )';

 echo "users... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}



        $sql = 'CREATE TABLE IF NOT EXISTS  `keys` ('
		        . ' `kid` INT NOT NULL AUTO_INCREMENT, '
		        . ' `uid` INT NOT NULL, '
		        . ' `pubkey` VARCHAR(2000) NOT NULL, '
		        . ' `created` VARCHAR(50) NOT NULL,'
		        . ' PRIMARY KEY (`kid`)'
        . ' )';

 echo "keys... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}



$sql = 'CREATE TABLE  IF NOT EXISTS  `userlist` ('
        . ' `id` INT NOT NULL AUTO_INCREMENT, '
        . ' `uid` INT NOT NULL, '
        . ' `hostuid` INT NOT NULL,'
        . ' PRIMARY KEY (`id`)'
        . ' )';

 echo "userlist... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}

$sql = 'CREATE TABLE IF NOT EXISTS  `userlistbak` ('
        . ' `id` INT NOT NULL AUTO_INCREMENT, '
        . ' `uid` INT NOT NULL, '
        . ' `hostuid` INT NOT NULL,'
        . ' PRIMARY KEY (`id`)'
        . ' )';



 echo "userlistbak... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}




        $sql = 'CREATE TABLE IF NOT EXISTS `sessions` ('
		        . ' `created` VARCHAR(20) NOT NULL, '
		        . ' `lastseen` VARCHAR(20) NOT NULL, '
		        . ' `uid` INT NOT NULL, '
		        . ' `sessionid` VARCHAR(20) NOT NULL, '
		        . ' `secret` VARCHAR(20) NOT NULL, '
		        . ' `offset` INT NOT NULL, '
		        . ' `ip` VARCHAR(20) NOT NULL, '
		        . ' `country` VARCHAR(2) NOT NULL, '
		        . ' `device` VARCHAR(4) NOT NULL, '
		        . ' `valhash` VARCHAR(32) NOT NULL, '
		        . ' `lastsalt` VARCHAR(10) NOT NULL'
        . ' )';

 echo "sessions... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}

        $sql = 'CREATE TABLE IF NOT EXISTS  `knowndevices` ('
		        . ' `created` VARCHAR(20) NOT NULL, '
		        . ' `uid` INT NOT NULL, '
		        . ' `device` VARCHAR(4) NOT NULL'
        . ' )';

 echo "knowndevices... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}

    $sql = ' CREATE TABLE IF NOT EXISTS `messages` ('
 . ' `mid` INT NOT NULL AUTO_INCREMENT,'
 . ' `fromuid` INT NOT NULL,'
 . ' `touid` INT NOT NULL,'
 . ' `text` MEDIUMTEXT,'
 . ' `created` VARCHAR(50) NOT NULL,'
 . ' `sent` VARCHAR(50) NOT NULL,'
 . ' `received` VARCHAR(50) NOT NULL,'
 . ' `read` VARCHAR(50) NOT NULL,'
 . ' `revoked` VARCHAR(50) NOT NULL,'
 . ' `failed` INT DEFAULT \'0\' NOT NULL,'
 . ' PRIMARY KEY (`mid`)'
 . ' )';


  $sql2 = 'ALTER TABLE `messages` CHANGE `text` `text` MEDIUMTEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL';

 echo "messages... ";
 if (mysql_query($sql) && mysql_query($sql2)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}



$sql = 'CREATE TABLE `attack` ('
        . ' `id` INT NOT NULL AUTO_INCREMENT, '
        . ' `uid` INT NOT NULL, '
        . ' `timestamp` VARCHAR(50) NOT NULL, '
        . ' `ip` VARCHAR(20) NOT NULL, '
        . ' `country` VARCHAR(2) NOT NULL, '
        . ' `browser` VARCHAR(100) NOT NULL, '
        . ' `type` INT NOT NULL, '
        . ' `cmd` VARCHAR(20) NOT NULL,'
        . ' PRIMARY KEY (`id`)'
        . ' )';

 echo "attack... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}


$sql = 'CREATE TABLE `requests` ('
        . ' `timestamp` VARCHAR(50) NOT NULL, '
        . ' `ip` VARCHAR(20) NOT NULL '
        . ' )';

 echo "requests... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}



$sql = 'CREATE TABLE `groups` ('
        . ' `id` INT NOT NULL AUTO_INCREMENT, '
        . ' `name` VARCHAR(20) NOT NULL, '
        . ' `created` VARCHAR(50) NOT NULL, '
        . ' `secret` VARCHAR(8) NOT NULL, '
        . ' PRIMARY KEY (`id`)'
        . ' )';


 echo "groups... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}


$sql = 'CREATE TABLE `groupmembers` ('
        . ' `groupid` INT NOT NULL, '
        . ' `uid` INT NOT NULL, '
        . ' `joined` VARCHAR(50) NOT NULL, '
        . ' `invited` INT NOT NULL'
        . ' )';

 echo "groupmembers... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED, DO MANUALLY:<BR>".htmlentities($sql)."<BR>";}


 $sql = "GRANT SELECT , INSERT , UPDATE , DELETE , CREATE , DROP , INDEX , ALTER  ON `".$DBNAME."` . * TO '".$DBUSER."'@'".$DBURL."';";
 echo "<BR>Granting permissions... ";
 if (mysql_query($sql)) {echo "OK<BR>";} else {echo "FAILED<BR>".htmlentities($sql)."<BR>";}



 printf("<BR><BR>Setup completed. You should delete the file 'setup.php' immediately.");


?>