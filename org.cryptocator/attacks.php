<?

 //error_reporting(-1);
 //ini_set('display_errors',1);
 //ini_set('display_startup_errors',1);
 //error_reporting (E_ERROR | E_WARNING | E_PARSE); // This will NOT report uninitialized variables
 // Turnoff all error reporting
 //error_reporting(0);
 ini_set('display_errors', 0);
 ini_set('log_errors', 0);

 require('config.php');
 include('Crypt/RSA.php');

 $WITHDRAWTEXT = "U[ message withdrawn ]";

//================================================================================================
//================================================================================================


 function opendb() {
     global $WEBMASTER;
     global $DBUSER;
     global $DBPWD;
     global $DBURL;
     $dbs = @mysql_connect($DBURL,$DBUSER,$DBPWD);
     if(!$dbs) { echo '-CANNOT ACCESS DATABASESERVER, PLEASE CONTACT THE SYSTEM ADMINISTARTOR AT '.$WEBMASTER; exit;}
     return $dbs;
 }

 function closedb($dbs) {
	mysql_close($dbs);
 }

 $connection = opendb();
 $db = 0;
 if ($connection) $db =  mysql_select_db($DBNAME,$connection);
 if(!$db) {
 	  echo '-CANNOT ACCESS DATABASE, PLEASE CONTACT THE SYSTEM ADMINISTARTOR AT '.$WEBMASTER;
 	  exit;
 }


 function printAttacks() {
       $query2 = "SELECT `timestamp`, `ip`, `country`, `browser`, `type`, `cmd` FROM `attack` ORDER BY id DESC";
       //printf($query2."<BR>");
       $result2 = mysql_query($query2);
 	   if (mysql_num_rows($result2) > 0) {
 	   		while($row = mysql_fetch_array($result2,MYSQL_ASSOC)) {
	 	       $e = implode(" ",$row);
	 	       $f = explode(" ",$e);
	 	       $attacktime = date("D M j G:i:s T Y", $f[0]);
	 	       printf($f[1]." \n");
	 	       printf($attacktime." \n");
	 	       printf(getAttackName($f[4])." \n");
	 	       printf($f[5]." \n");
	 	       printf($f[2]." \n");
	 	       printf($f[3]." \n");
	 	       printf("\n\n");

	    	}
 	   }
 }

 header("Content-Type: text/plain");

 printf("\n");
 printf("==============================================================\n");
 printf("==  WWW.CRYPTSECURE.ORG - WE EXPOSE ANY ATTACKS ON PRIVACY  ==\n");
 printf("==============================================================\n");
 printf("\n");
 printf("R E C E N T   A T T A C K S:\n");
 printf("\n");
 printf("\n");

 printAttacks();


 closedb($connection);


?>