<?
/*
 * Copyright (c) 2015, Christian Motika. Dedicated to Sara.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * all contributors, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, an acknowledgment to all contributors, this list of conditions
 * and the following disclaimer in the documentation and/or other materials
 * provided with the distribution.
 *
 * 3. Neither the name Delphino Cryptocator nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * 4. Free or commercial forks of Cryptocator are permitted as long as
 *    both (a) and (b) are and stay fulfilled:
 *    (a) This license is enclosed.
 *    (b) The protocol to communicate between Cryptocator servers
 *        and Cryptocator clients *MUST* must be fully conform with
 *        the documentation and (possibly updated) reference
 *        implementation from cryptocator.org. This is to ensure
 *        interconnectivity between all clients and servers.
 *
 * THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS “AS IS” AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


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

 $REVOKEDTEXT = "U[ message revoked ]";

//================================================================================================
//================================================================================================

// SETUP THE KEYS.PHP FILE CONTAINING PUBLIC AND PRIVATE KEY //

   $keyfile = "keys.php";
   if (!file_exists($keyfile)) {
	   // Both
	   $rsa = new Crypt_RSA();

       $rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_RAW);

	   // PHP seclib
	   //define('CRYPT_RSA_SMALLEST_PRIME', 512);
	   $rsa->setPassword(); // clear the password if there was one
	   extract($rsa->createKey(512)); // 1024 keylen makes problems with java!!! 512 seems to work!
//	   extract($rsa->createKey(2048)); // 1024 keylen makes problems with java!!! 512 seems to work!

	   $public_key = $publickey;   //$rsa->getPublicKey();
       $private_key = $privatekey; //$rsa->getPrivateKey();

	   // Crypt RSA PEAR
	   //$key_pair = new Crypt_RSA_KeyPair(512);
	   //$public_key = $key_pair->getPublicKey()->toString();
       //$private_key = $key_pair->getPrivateKey()->toString();

	   // USELESS START
	   //$rsa->setEncryptionMode(public_key);
	   //$rsa->setPrivateKeyFormat(CRYPT_RSA_PRIVATE_FORMAT_PKCS1);
	   //$rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_PKCS1);
	   //$rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_PKCS8); /// PKCS8 can be used with android?!
	   //$rsa->setHash('sha1');
       //$rsa->setMGFHash('sha1');
       //$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);
       //$rsa->setPrivateKeyFormat(CRYPT_RSA_PRIVATE_FORMAT_PKCS1);
       //$rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_PKCS1);
       //printf("@".$public_key."@<BR><BR>");
       //$MyPemStr = base64_encode($key_pair->toPEMString());
       //$public_key = str_replace("-----BEGIN RSA PUBLIC KEY-----", "", $public_key);
 	   //$public_key = str_replace("-----END RSA PUBLIC KEY-----", "", $public_key);
 	   //$public_key = str_replace("\r", "", $public_key);
 	   //$public_key = str_replace("\n", "", $public_key);
	   // IS ALREADY BASE64 ENCODED!!!
	   //$public_key64 = base64_encode($public_key);
	   // USELESS END

	    $private_key64 = base64_encode($private_key);

	    $pubExp = $publickey["e"]->toHex();
	    $pubMod = $publickey["n"]->toHex();
	    $public_ExpAndMod = $pubExp."#".$pubMod;

		$fh = fopen($keyfile, 'w') or die("can't open file");
		fwrite($fh, "<? function getServerPubKey() {return \"".$public_ExpAndMod."\";} ");
    	fwrite($fh, "function getServerPrivKey() {return base64_decode(\"".$private_key64."\");} ?>");
    	fclose($fh);
  }
  if (file_exists($keyfile)) {
    require($keyfile);
  }


  //--------------------------------------------------------------
  //--------------------------------------------------------------

 function loadServerPubKey($rsa) {
 	$rawvalues = getServerPubKey();
    printf("rawvalues:".$rawvalues."<BR>");
    $values = explode("#", $rawvalues);
    printf("values:".$values."<BR>");
    if (count($values) == 2) {
       $pubExp = $values[0];
       $pubMod = $values[1];
       printf("pubExp:".$pubExp."<BR>");
       printf("pubMod:".$pubMod."<BR>");
	   $rsa->loadKey(
        array(
         'e' => new Math_BigInteger($pubExp),
         'n' => new Math_BigInteger($pubMod)
        )
	   );
    }
 }

  //--------------------------------------------------------------

 function serverEnc($plain_text) {
    $rsa = new Crypt_RSA();
    $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
 	loadServerPubKey($rsa);
	return $rsa->encrypt($plain_text);

 	//$rsa->loadKey(getServerPubKey());
    //$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS8);
    //$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);
    //$public_key = getServerPubKey();
    //$key = Crypt_RSA_Key::fromString($public_key);
    //$rsa_obj = new Crypt_RSA;
    //$encryptedText = $rsa_obj->encrypt($plain_text, $key);
    //return $encryptedText;
 }

  //--------------------------------------------------------------

 function serverDec($enc_text) {
     $rsa = new Crypt_RSA();
     $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
 	 $rsa->loadKey(getServerPrivKey());
 	 return $rsa->decrypt($enc_text);

	 //$rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_PKCS1);
     //printf("serverKeyBase64:".base64_encode($rsa->getPublicKey())."<BR><BR>");
     //$private_key = getServerPrivKey();
     //$key = Crypt_RSA_Key::fromString($private_key);
     //$rsa_obj = new Crypt_RSA;
     //$rsa_obj->setParams(array('dec_key' => $key));
     //return $rsa_obj->decrypt($enc_text);
}

  //--------------------------------------------------------------
  //--------------------------------------------------------------

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
 if(!$db) {
 	  echo '-CANNOT ACCESS DATABASE, PLEASE CONTACT THE SYSTEM ADMINISTARTOR AT '.$WEBMASTER;
 	  exit;
 }


 //--------------------------------------------------------------
 //--------------------------------------------------------------
 //--------------------------------------------------------------
 //--------------------------------------------------------------

  $cmd = $_GET['cmd'];
  $postCmd = $_POST['cmd'];
  if ($postCmd != "") {
   	  $cmd = $postCmd;
  }
  $pwd = $_GET['pwd'];
  $user = $_GET['user'];
  $email = $_GET['email'];
  $val = $_GET['val'];
  $postVal = $_POST['val'];
  if ($postVal != "") {
   	  $val = $postVal;
  }
  $ip = $_SERVER['REMOTE_ADDR'];
  $browser = $_SERVER['HTTP_USER_AGENT'];
  $host = $_GET['host'];
  $postHost = $_POST['host'];
  if ($postHost != "") {
   	  $host = $postHost;
  }
  $session = $_GET['session'];
  $postSession = $_POST['session'];
  if ($postSession != "") {
   	  $session = $postSession;
  }
  $val1 = $_GET['val1'];
  $val2 = $_GET['val2'];
  $val3 = $_GET['val3'];



//  	  printf("\n");
//  	  printf("cmd: ".$cmd."\n");
//  	  printf("postCmd: ".$postCmd."\n");
//  	  printf("sessionlen: ".strlen($session)."\n");
//  	  printf("session: ".$session."\n");
//  	  printf("postSession: ".$postSession."\n");
//  	  printf("vallen: ".strlen($val)."\n");
//  	  printf("val: ".$val."\n");
//  	  printf("postVal: ".$postVal."\n");
//  	  printf("host: ".$host."\n");
//  	  printf("postHost: ".$postHost."\n");
//  	  printf("valiso: ".utf8_decode($val)."\n");
//  	  printf("pwd: ".$pwd."\n");
//  	  printf("user: ".$user."\n");
//  	  printf("email: ".$email."\n");
//  	  printf("ip: ".$ip."\n");
//  	  printf("host: ".$host."\n");
//  	  printf("val1: ".$val1."\n");
//  	  printf("val2: ".$val2."\n");
//  	  printf("val3: ".$val3."\n");
//  	  exit;


//  if ($cmd == "send") {
//	  printf("\n");
//	  printf("cmd: ".$cmd."\n");
//	  printf("host: ".$host."\n");
//	  printf("sessionlen: ".strlen($session)."\n");
//	  printf("session: ".$session."\n");
//	  printf("vallen: ".strlen($val)."\n");
//	  printf("val: ".$val."\n");
//	  printf("valiso: ".utf8_decode($val)."\n");
//	  exit;
//  }

//  if ($cmd == "sendX") {
//	 header("Content-Type: text/plain");
// 	 printf("\n");
//	  printf("cmd: ".$cmd."\n");
//	  printf("host: ".$host."\n");
//	  printf("sessionlen: ".strlen($session)."\n");
//	  printf("session: ".$session."\n");
//	  printf("vallen: ".strlen($val)."\n");
//	  printf("val: ".$val."\n");
//	  printf("valiso: ".utf8_decode($val)."\n");
//

//	  exit;
//	  printf("cmd: ".$cmd."<BR>");
//	  printf("host: ".$host."<BR>");
//	  printf("session: ".strlen($session)."<BR>");
//	  printf("vallen: ".strlen($val)."<BR>");
//	  printf("val: ".$val."<BR>");
//	  exit;
//  }


 //--------------------------------------------------------------
 //--------------------------------------------------------------
 //--------------------------------------------------------------
 //--------------------------------------------------------------


 // Add this reuest
 addRequest();
 // CHECK IF DOS ATTACK //
 $numrequests = countRequests(($dostimemin*60));
 //printf($numrequests."/".$dosmaxnumreq);
 if ($numrequests > $dosmaxnumreq) {
 		// GUARD AGAINST TOO MANY REQUESTS
    	if (!isDosAttackListed()) {
    	    addAttack("n/a", "", 4);
    	}
 		denyService();
 }
 // Clean up
 removeRequests(($dostimemin*60));


 // CHECK IF HAVE TO BAN //
 if ($bantimemin > 0) {
 	   $timeout = date("U") - ($bantimeout*60*60);


       $query2 = "SELECT `timestamp` FROM `attack` WHERE `ip` = '".$ip."' AND 'timestamp' > '".$timeout."' ORDER BY `timestamp` DESC";
       $result2 = mysql_query($query2);

       $cnt = mysql_num_rows($result2);

       if ($cnt > 0) {
       	  // POSSIBLY BANNING THIS IP //
          $row = mysql_fetch_array($result2,MYSQL_ASSOC);
          $e = implode(" ",$row);
          $f = explode(" ",$e);

          $lastattack = $f[0];


       	  $bantime = (($bantimemin * $cnt) * $bantimeinc)/100;

       	  $released = (date("U") - ($bantime * 60) - $lastattack) / 60;

       	  //printf($bantime." Minutes - Try again in ".$released." Minutes<BR>");

       	  if ($lastattack > date("U") - ($bantime * 60)) {
       	  		// NOW BANNING //
       	  		denyService();
       	  }
       }
 }


 $bantimeinc = 100; // increase 100% == double the bantime after each attack



  //--------------------------------------------------------------

  function denyService() {
   printf("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
<html><head>
<title>500 Internal Server Error</title>
</head><body>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error or
misconfiguration and was unable to complete
your request.</p>
<p>Please contact the server administrator,
 [no address given] and inform them of the time the error occurred,
and anything you might have done that may have
caused the error.</p>
<p>More information about this error may be available
in the server error log.</p>
<hr>
<address>Apache/2.2.22 (Debian) Server at ".$_SERVER['HTTP_HOST']." Port 80</address>
</body></html>
");
   exit;
  }


  //--------------------------------------------------------------

  function isActive($uid) {
   	$uid = intval($uid);

    $backvalue = false;
    $result = mysql_query("SELECT active FROM users WHERE uid = '".$uid."'");
    if (mysql_num_rows($result) > 0) {
        $row = mysql_fetch_array($result,MYSQL_ASSOC);
        $e = implode(" ",$row);
        $f = explode(" ",$e);
        if ($f[0] == 1) $backvalue = true;
    }
    return $backvalue;
 }

  //--------------------------------------------------------------

  function emailok($email) {
    $email = trim($email);

    $foundillegal = false;
    $found_at = false;
    $found_point = false;
    $host = "";
    $ext  = "";
    $name = "";

    for ($i = 0;$i < strlen($email); $i++) {
      $zeichen = substr($email,$i,1);

      $ascii = ord($zeichen);
      $ok = false;
      if ($zeichen == ".") $ok = true;
      if ($zeichen == "/") $ok = true;
      if ($zeichen == "@") $ok = true;
      if (($ascii >= 48)&&($ascii <= 57)) $ok = true;   //Zahl
      if (($ascii >= 65)&&($ascii <= 90)) $ok = true;   //GROSSE buschstaben
      if (($ascii >= 97)&&($ascii <= 122)) $ok = true;  //kleine buschstaben
      if (($ascii == 95)||($ascii == 45)) $ok = true; // "_" imd "-"
      if (!$ok) $foundillegal = true;

      if ($zeichen == "@") $found_at = true;
      if (($zeichen == ".")&&($found_at)) $found_point = true;

      if (($zeichen == "@")||($zeichen == ".")) $zeichen = "";

      if (($found_at)&&($found_point)) {
       $ext .= $zeichen;
      }
      else if ($found_at) {
       $host .= $zeichen;
      }
      else {
       $name .= $zeichen;
      }
    }//next $i

    //prüfen
    $allesok = true;
    if (!(found_at)) $allesok = false;
    if (!(found_point)) $allesok = false;
    if (strlen($host)< 1) $allesok = false;
    if (strlen($name)< 1) $allesok = false;
    if (strlen($ext)< 1) $allesok = false;
    if ($foundillegal) $allesok = false;

    return $allesok;
  }

  //--------------------------------------------------------------


 function getUID($email) {
   $backvalue = -1;
   if ($email == "email") {
   		return -1;
   }
   $result = mysql_query("SELECT uid FROM users WHERE email LIKE  '".$email."'");
   if (mysql_num_rows($result) > 0) {
       $row = mysql_fetch_array($result,MYSQL_ASSOC);
       $e = implode(" ",$row);
       $f = explode(" ",$e);
       $backvalue = $f[0];
   }
   return $backvalue;
 }

  //--------------------------------------------------------------
  //--------------------------------------------------------------

  function login($uid, $pwd) {
 $uid = intval($uid);
   $result = mysql_query("SELECT pwd FROM users WHERE uid = '".$uid."'");
   if (mysql_num_rows($result) > 0) {
       $row = mysql_fetch_array($result,MYSQL_ASSOC);
       $e = implode(" ",$row);
       $f = explode(" ",$e);
       //printf($pwd." -login2-> ".md5($pwd)." == ".$f[0]."<BR>");
       if (md5($pwd) == $f[0]) {
       		return true;
       }
   }
   return false;
  }

  // test if the current pw is a changed one that is not confirmed/activated yet!
  // just to make the error message more transparent
  function loginPWChange($uid, $pwd) {
 	$uid = intval($uid);
   $result = mysql_query("SELECT pwdchange FROM users WHERE uid = '".$uid."'");
   if (mysql_num_rows($result) > 0) {
       $row = mysql_fetch_array($result,MYSQL_ASSOC);
       $e = implode(" ",$row);
       $f = explode(" ",$e);
       //printf($pwd." -login2-> ".md5($pwd)." == ".$f[0]."<BR>");
       if (md5($pwd) == $f[0]) {
       		return true;
       }
   }
   return false;
  }




  //--------------------------------------------------------------

 function sendWelcomeMessage($uid) {
 	$uid = intval($uid);
    $createdTimeStamp = date("U")."000";
    $welcome = "UWelcome to Delphino Cryptocator!@@@NEWLINE@@@@@@NEWLINE@@@Your account has just been activated. You can now exchange securely encrypted messages with other people who also value uncompromised privacy.@@@NEWLINE@@@@@@NEWLINE@@@Give your UID \'".$uid."\' to anyone who should be able to add you. Ask friends about their UIDs in order to add them. To add UIDs, go to the main window and select \'Add User\' from the context menu.@@@NEWLINE@@@@@@NEWLINE@@@More information here: http://www.cryptocator.org@@@NEWLINE@@@@@@NEWLINE@@@Tell a good friend about Cryptocator if you like it!";
 	sendText("0", $uid, $welcome, $createdTimeStamp);
 }

  //--------------------------------------------------------------

 function activateAccount($activation) {
   if ($activation == "activation") {
   		return;
   }
   $result = mysql_query("SELECT uid FROM users WHERE activation = '".$activation."'");
   if (mysql_num_rows($result) > 0) {
       $row = mysql_fetch_array($result,MYSQL_ASSOC);
       $e = implode(" ",$row);
       $f = explode(" ",$e);
       $uid = $f[0];

       $query = "UPDATE users SET activation = '' WHERE uid = '".$uid."'";
       $query2 = "UPDATE users SET active = '1' WHERE uid = '".$uid."'";
	   $result = mysql_query($query);
	   $result2 = mysql_query($query2);
       if ($result && $result2) {
             // Send welcome mesage
             sendWelcomeMessage($uid);
	   		 return true;
       } else {
	       	 return false;
   	   }
   }
   return false;
 }


  //--------------------------------------------------------------


 function getPWDChange($uid) {
   $uid = intval($uid);
   $backvalue = -1;
   $result = mysql_query("SELECT pwdchange FROM users WHERE uid = '".$uid."'");
   if (mysql_num_rows($result) > 0) {
       $row = mysql_fetch_array($result,MYSQL_ASSOC);
       $e = implode(" ",$row);
       $f = explode(" ",$e);
       $backvalue = $f[0];
   }
   return $backvalue;
 }

  //--------------------------------------------------------------

 function activatePwd($activation) {
   if ($activation == "activation") {
   		return;
   }
   $result = mysql_query("SELECT uid FROM users WHERE activation = '".$activation."'");
   if (mysql_num_rows($result) > 0) {
       $row = mysql_fetch_array($result,MYSQL_ASSOC);
       $e = implode(" ",$row);
       $f = explode(" ",$e);
       $uid = $f[0];

       $query = "UPDATE users SET activation = '' WHERE uid = '".$uid."'";

       //move changed new password from pwdchange to pwd
       $pwdchange = getPWDChange($uid);

       $query2 = "UPDATE users SET pwd = '".$pwdchange."' WHERE uid = '".$uid."'";
       $query3 = "UPDATE users SET pwdchange = '' WHERE uid = '".$uid."'";

	   $result = mysql_query($query);
	   $result2 = mysql_query($query2);
	   $result3 = mysql_query($query3);
       if ($result && $result2 && $result3) {
	   		 return true;
       } else {
	       	 return false;
   	   }
   }
   return false;
 }

  //--------------------------------------------------------------
  //--------------------------------------------------------------

  //-------
  // ERROR COUNTER
  //-------
  function setPwdErrCnt($uid, $cnt) {
      	$query = "UPDATE users SET pwderr = '".$cnt."' WHERE uid = '".$uid."'";
  	    $result = mysql_query($query);
  	    if ($result) {
  	     	return true;
  	    } else {
  	    	return false;
  	    }
  }
  function getPwdErrCnt($uid) {
   	$result = mysql_query("SELECT pwderr FROM users WHERE uid = '".$uid."'");
   	if (mysql_num_rows($result) > 0) {
       $row = mysql_fetch_array($result,MYSQL_ASSOC);
       $e = implode(" ",$row);
       $f = explode(" ",$e);
       return $f[0];
     }
     return 0;
  }
  function resetPwdErrCnt($uid) {
      setPwdErrCnt($uid, 0);
  }
  function incrementPwdErrCnt($uid) {
      setPwdErrCnt($uid, 1 + getPwdErrCnt($uid));
  }
  //-------


  //-------
  // Check country
  //-------
  function getLastCountry($uid) {
   	$result = mysql_query("SELECT country FROM sessions WHERE uid = '".$uid."' ORDER BY created DESC");
   	if (mysql_num_rows($result) > 0) {
       $row = mysql_fetch_array($result,MYSQL_ASSOC);
       $e = implode(" ",$row);
       $f = explode(" ",$e);
       return $f[0];
     }
     return 0;
  }
  function checkCountry($uid, $country) {
	if ($country == "") {
	   return;
	}
	$oldcountry = getLastCountry($uid);
	if ($oldcountry != $country) {
		// SEND WARNING : MORE THAN 10x wrong password
   		sendSecurityWarning($uid, 2, $country, $oldcountry, "");
	}
  }
  //-------



  //-------
  // Check devices
  //-------
  function haveUsedDevice($uid, $device) {
   	$result = mysql_query("SELECT device FROM knowndevices WHERE uid = '".$uid."' AND device = '".$device."'");
   	if (mysql_num_rows($result) > 0) {
   	   return true;
     }
     return false;
  }
  function addDevice($uid, $device) {
    $query = "INSERT INTO knowndevices (created, uid, device)
               VALUES ('".$created."','".$uid."','".$device."')";
    //printf($query."<BR>");
    $result = mysql_query($query);
    if ($result) {
		 return true;
    } else {
    	 return false;
    }
  }
  //-------



  //-------
  // CHECK / UPDATE LASTSALT
  function getLastSalt($sessionid) {
     $backvalue = -1;
     $result = mysql_query("SELECT `lastsalt` FROM `sessions` WHERE `sessionid` = '".$sessionid."'");
     if (mysql_num_rows($result) > 0) {
         $row = mysql_fetch_array($result,MYSQL_ASSOC);
         $e = implode(" ",$row);
         $f = explode(" ",$e);
         $backvalue = $f[0];
     }
     return $backvalue;
   }

   function updateLastSalt($session, $lastsalt) {
      	$query = "UPDATE `sessions` SET `lastsalt` = '".$lastsalt."' WHERE `sessionid` = '".$session."'";
      	//printf($query."<BR>");
  	    $result = mysql_query($query);
  	    if ($result) {
  	     	return true;
  	    } else {
  	    	return false;
  	    }
   }
  //-------





  //-------
  //-------


  function addAttack($cmd, $uid, $type) {
 	$uid = intval($uid);
  	global $ip;
  	global $browser;
    $timestamp = date("U");
    $country = getCountry();

    $query = "INSERT INTO `attack` (uid, timestamp, ip, country, browser, type, cmd)
               VALUES ('".$uid."','".$timestamp."','".$ip."','".$country."','".$browser."','".$type."','".$cmd."')";

   // printf($query."<BR>");
    $result = mysql_query($query);
    if ($result) {
    	return true;
    } else {
        return false;
    }
  }


  function isDosAttackListed() {
  	global $ip;
  	global $dostimemin;
    $timebarrier = date("U") - $dostimemin*60;
       $query2 = "SELECT `timestamp` FROM `attack` WHERE `ip` = '".$ip."' AND `timestamp` > ".$timebarrier."";
	   //printf(date("U")."<BR>".$query2."<BR>");
       $result2 = mysql_query($query2);
       $cnt = mysql_num_rows($result2);
	   return ($cnt > 0);
  }

  //-------
  //-------


  function removeRequests($secondsback) {
       $timebarrier = date("U") - $secondsback;
       $query2 = "DELETE FROM `requests` WHERE `timestamp` < '".$timebarrier."'";
       $result2 = mysql_query($query2);
	   return;
  }

  function countRequests($secondsback) {
  	global $ip;
       $timebarrier = date("U") - $secondsback;
       $query2 = "SELECT `timestamp` FROM `requests` WHERE `ip` = '".$ip."' AND `timestamp` > ".$timebarrier."";
	   //printf(date("U")."<BR>".$query2."<BR>");
       $result2 = mysql_query($query2);
       $cnt = mysql_num_rows($result2);
	   return $cnt;
  }


  function addRequest() {
  	global $ip;
    $timestamp = date("U");
    $query = "INSERT INTO `requests` (timestamp, ip)
               VALUES ('".$timestamp."','".$ip."')";
   // printf($query."<BR>");
    $result = mysql_query($query);
    if ($result) {
    	return true;
    } else {
        return false;
    }
  }


  //-------
  //-------



 // this returns quickly the UID for the current session
 function fastLogin($sessionid)  {
 			if($sessionid == "sessionid") {
 				return -1;
 			}
  		    $result = mysql_query("SELECT uid FROM sessions WHERE sessionid = '".$sessionid."' ORDER BY created DESC");
			if (mysql_num_rows($result) > 0) {
			       $row = mysql_fetch_array($result,MYSQL_ASSOC);
			       $e = implode(" ",$row);
			       $f = explode(" ",$e);

			       return $f[0];
			}
			return -1;
 }


  // returns the extracted UID
  // expect session= md5(sessionid#timestampinseconds#secret#salt)#sessionid#salt
  function loginTmp($session) {
  		global $cmd;

  		$values = explode("#", $session);
  		if (count($values) == 3) {
  		    $val = $values[0];
  		    $sessionid = $values[1];
  		    $salt = $values[2];

  		    // already used the salt last time?!?
  		    if ($salt == getLastSalt($sessionid)) {
  		    	//... then deny!
  		    	// register attack!
  		    	addAttack($cmd, fastLogin($sessionid), 1);
  		    	return -1;
  		    }


			if ($sessionid == "sessionid") {
					return -1;
			}

//			       printf("val:".$val."<BR>");
//			       printf("sessionid:".$sessionid."<BR>");
//			       printf("salt:".$salt."<BR>");


  		    $result = mysql_query("SELECT uid,secret,offset FROM sessions WHERE sessionid = '".$sessionid."' ORDER BY created DESC");
			if (mysql_num_rows($result) > 0) {
			       $row = mysql_fetch_array($result,MYSQL_ASSOC);
			       $e = implode(" ",$row);
			       $f = explode(" ",$e);

			       $uid = $f[0];
			       $secret = $f[1];
			       $offset = $f[2];
			       $servertime = date("U");

			       // now state estimation for usertime
			       $estimatedusertime = $servertime - $offset;
			       $fragmentestimatedusertime = floor($estimatedusertime/100);

			       $vgltmpsession = $sessionid."#".$fragmentestimatedusertime."#".$secret."#".$salt;
			       $md5vgltmpsession = md5($vgltmpsession);
			       //printf("vgltmpsession:".$vgltmpsession." --> ".$md5vgltmpsession."<BR>");
			       //printf($val." =?= ".$md5vgltmpsession."<BR>");

				   if ($val == $md5vgltmpsession) {
				   		updateLastSalt($sessionid, $salt);
				   		//printf("BLAA");
				   		//exit;
				   		return $uid;
				   }
		    }
  		}
  		return -1;// not valid temp-session
  }

 // ---------



  //-------
  // Check valhash - we want to allow the usage of each login val only once and discard it the next time!!!!
  //-------
  function haveUsedVal($valhash) {
  		$now = date("U");
  		$fivedaysago = $now - (60*60*24*5);
  		$query = "SELECT created FROM sessions WHERE valhash = '".$valhash."' AND created > '".$fivedaysago."'";
     	$result = mysql_query($query);
     	//printf($query."<BR><BR>");
     	if (mysql_num_rows($result) > 0) {
     	   return true;
       }
       return false;
   }
  //-------


  function removeOldSession($user) {
  }


  // Login with uid or email
  // Extendedlogin will print uid, email and username additionally

  // delphino.net/cryptocator/index.php?cmd=login2&val=uid%23passw%23secret%23timestamp%23HTC1

  // shorthash() == first 5 symbols from md5() hash!
  // expect val1= uid or email
  // expect val2= password
  // expect val3= uidshorthash#passwordshorthash#secret#timestamp   (timestamp in seconds!!!!)%DEVICEID(4)
  function login2($val1, $val2, $val3, $extendedLogin) {
  	    global $ipaddress;


		$userHash = substr(md5($val1), 0, 5);
		$passwordHash = substr(md5($val2), 0, 5);

        $val1 = base64_decode($val1);
        $val1 = serverDec($val1);

  	    // keep the hash of the val for disallowing later sessions within the last 5 days!
  	    $valhash = md5($val3);
  	    if (haveUsedVal($valhash)) {
	    	addAttack("login", $val1, 2);
  			return "-88"; // reusage attack, do not allow this!!!
  	    }

        //printf("ARRIVED:".$val."<BR><BR>");
        //printf("DECODED BASE64:".$val."<BR><BR>");
        //printf("DECHIPHER:".$val2."<BR><BR>");
        //$val2 = $val;

        //printf("val1:".$val1."<BR>");
        //printf("val2:".$val2."<BR>");
        //printf("val3:".$val3."<BR><BR>");



        $val2 = base64_decode($val2);
        $val2 = serverDec($val2);
        $val3 = base64_decode($val3);
        $val3 = serverDec($val3);


  		$uidOrEmail = $val1;
  		$uid = $uidOrEmail;
  		if (!is_numeric($uidOrEmail)) {
  		         // if this is an email, give the right UID
  		         $uid = getUID($uidOrEmail);
  		}
  		$password = $val2;

        //printf("uid:".$uid."<BR>");

        //printf("userHash:".$userHash."<BR>");
        //printf("passwordHash:".$passwordHash."<BR>");


        //printf("val1:".$val1."<BR>");
        //printf("val2:".$val2."<BR>");
        //printf("val3:".$val3."<BR><BR>");

  		$values = explode("#", $val3);
  		//printf(count($values)."<BR><BR>");
  		if (count($values) == 5) {
  		    $userHashVgl = $values[0];
  		    $passwordHashVgl = $values[1];

  		    if ($userHashVgl != $userHash) {
  		        return "-98"; // wrong hash
  		    }
  		    if ($passwordHashVgl != $passwordHash) {
  		        return "-99"; // wrong hash
  		    }

  		    //printf("uidOrEmail:".$uidOrEmail."<BR><BR>");
  		    //printf("password:".$password."<BR><BR>");
  		    //printf("secret:".$secret."<BR><BR>");
  		    $secret = $values[2];
  		    $timestamp = $values[3];
  		    $device = $values[4];

     		if (!isActive($uid)) {
     		    return "-4"; // -4 == account not activated!
     		}
  		    if (login($uid, $password)) {
  		    	// password matches
			    $country = getCountry();
			    checkCountry($uid, $country);
			    if (!haveUsedDevice($uid, $device)) {
	  	        	// SEND WARNING : SWITCHED TO UNKNOWN DEVICE
	  	        	sendSecurityWarning($uid, 1, "", "", $device);
	  	        	addDevice($uid, $device);
			    }
			    $returnVal = insertSession($uid, $secret, $timestamp, $device, $country, $valhash);
			    if ($extendedLogin) {
			    	$returnVal .= "#".encUid($uid, $uid)."#".encText($uid, getEmail($uid))."#".encText($uid, getUsername($uid));
			    }
		  		return $returnVal;
		  	} else if (loginPWChange($uid, $password)) {
		     	return "-11"; // -11 == new password not active
		    } else if ($password == "") {
		     	// NO PASSWORD IS JUST INVALID
  		    } else {
	  	        incrementPwdErrCnt($uid);
	  	        if (getPwdErrCnt($uid) >= 10) {
	  	        	// SEND WARNING : MORE THAN 10x wrong password
	  	        	sendSecurityWarning($uid, 0, "", "", "");

	  	        	addAttack("login", $uid, 3);
	  	        }
  		    	return "-44 ".$password; // password wrong
  		    }
  		}
  		else {
  			return "-55"; // login2 error
  		}
  }



  function contains($haystack, $needle) {
	  return (strrpos($haystack, $needle) > -1);
  }

  //FIPS code: https://en.wikipedia.org/wiki/List_of_FIPS_country_codes
  function getCountry() {
    global $ipaddress;
    if (contains($ipaddress, "192.170.")) {
     	return "DE";
    }
    $iptolocation = 'http://api.hostip.info/country.php?ip=' . $ipaddress;
	$creatorlocation = file_get_contents($iptolocation);
 	return $creatorlocation;
  }

  function insertSession($uid, $secret, $usertimestamp, $device, $country, $valhash) {
  	global $ipaddress;
    $created = date("U");
    $lastseen = $created;
	$offset = $created - $usertimestamp;
	$sessionid = getRND(20);
    $query = "INSERT INTO sessions (created, lastseen, uid, sessionid, secret, offset, ip, country, device, valhash)
               VALUES ('".$created."','".$lastseen."','".$uid."','".$sessionid."','".$secret."','".$offset."','".$ipaddress."','".$country."','".$device."','".$valhash."')";

   // printf($query."<BR>");
    $result = mysql_query($query);
    if ($result) {
    	// Reset pwd err cnt
    	 $errorCount = getPwdErrCnt($uid);
         resetPwdErrCnt($uid);
		 return ("1#".$sessionid."#".$errorCount);
    } else {
    	 return -1;
    }
  }

  //--------------------------------------------------------------
  //--------------------------------------------------------------

 function createUser($username, $email, $pwd) {
 	global $rnduidincmin;
 	global $rnduidincmax;

    $query2 = "INSERT INTO users (username, email, pwd, registered, active)
               VALUES ('".$username."','".$email."','".$pwd."','".date("U")."000', 0)";

	if ($rnduidincmin < 0) {
		$rnduidincmin = 1;
	}
	if ($rnduidincmax < 0) {
		$rnduidincmax = 1;
	}
    $num = rand($rnduidincmin, $rnduidincmax);

    for ($i = 1; $i <= $num; $i++) {
	    $query = "INSERT INTO `users` (username, email, pwd, registered, active)
               VALUES ('system','system','system','".date("U")."000', 0)";
	    $result = mysql_query($query);
	    $query = "DELETE FROM `users` WHERE username = 'system'";
		$result = mysql_query($query);
    }

	// SET RANDOM AUTO INCREMENT FOR NEW UID
	//$query1 = "SET @@auto_increment_increment=".$num;
    //$result = mysql_query($query1);

    //print($query);
    //exit;
    $result = mysql_query($query2);
    if ($result) {
		 return (getUID($email));
    } else {
    	 return -1;
    }
 }

  //--------------------------------------------------------------

 function isRegistered($email) {
  	if ($email == "email") {
  		return false;
  	}
    $result = mysql_query("SELECT uid FROM users WHERE email LIKE '".$email."'");
    if (mysql_num_rows($result) > 0) {
        return true;
    }
    return false;
 }

  //--------------------------------------------------------------

 function getRND($len) {
        mt_srand((double) microtime()*1000000);
        $sessionid1 = md5(str_replace(".","",$REMOTE_ADDR) + mt_rand(100000,999999));
        $sessionid2 = md5(str_replace(".","",$REMOTE_ADDR) + mt_rand(100000,999999));
        $sessionid3 = md5(str_replace(".","",$REMOTE_ADDR) + mt_rand(100000,999999));
        $backvalue = substr($sessionid1.$sessionid2.$sessionid3,0,$len);
        return $backvalue;
 }//end function

 //--------------------------------------------------------------

 function getActivation($uid) {
 	$uid = intval($uid);
    $activation = getRND(50);
    $query = "UPDATE users SET activation = '".$activation."' WHERE uid = '".$uid."'";
    $result = mysql_query($query);
    if ($result) {
		 return $activation;
    } else {
    	 return -1;
    }
 }

  //--------------------------------------------------------------

  function getEmail($uid) {
 	$uid = intval($uid);
   $backvalue = -1;
   $result = mysql_query("SELECT email FROM users WHERE uid = '".$uid."'");
   if (mysql_num_rows($result) > 0) {
       $row = mysql_fetch_array($result,MYSQL_ASSOC);
       $e = implode(" ",$row);
       $f = explode(" ",$e);
       $backvalue = $f[0];
   }
   return $backvalue;
 }


  //--------------------------------------------------------------

  function getUsername($uid) {
 	$uid = intval($uid);
   $backvalue = -1;
   $result = mysql_query("SELECT username FROM users WHERE uid = '".$uid."'");
   if (mysql_num_rows($result) > 0) {
       $row = mysql_fetch_array($result,MYSQL_ASSOC);
       $e = implode(" ",$row);
       $f = explode(" ",$e);
       $backvalue = $f[0];
   }
   return $backvalue;
 }


 //--------------------------------------------------------------

 // replaces all found seach with replace strings
 // if replace is empty it uses removebracelets and checks if it can remove
 // blocks ... NEED to cleanupbracelets after all replaces are done

 function ReplaceTextEx($inText,
						 $Search,
						 $Replace,
						 $firstonly) {
		$backText = "";
		$lock = false;

		for ($i = 0; $i < strlen($inText); $i++) {
			 $Zeichen = substr($inText,$i,1);
			 $VGLCMD  = substr($inText,$i,strlen($Search));
			 if ((!$lock)&&($VGLCMD == $Search)) {
			 		$backText .= $Replace;
					$i += strlen($Search) -1;
					if ($firstonly) {
						$lock = true;
					}
			 }
			 else
				$backText .= $Zeichen;
		}//next i

        return $backText;
 }

 //--------------------------------------------------------------

 function ReplaceText($inText,
						 $Search,
					     $Replace) {
	   return (ReplaceTextEx($inText,$Search,$Replace,false));
 }

 //--------------------------------------------------------------

 //returns a string with the bodytext of a template mail
 function readmail($filename) {
     $backText = "";

     if ((file_exists($filename))) {
	     $handle = fopen($filename,"r");
	     while(!feof($handle)) {
	        $line = trim(fgets($handle, 1000));
	        $backText = $backText.$line."\n";
	     }//while
	     fclose($handle);
     }

     return $backText;
    }//end function

 //--------------------------------------------------------------

  function sendEmailRegister($uid, $username, $activation, $ip) {
    global $CONST_EMAILHEADER;
    global $BASEURL;

    $email = getEmail($uid);
    $backvalue = false;

    if ($email) {
	    $EMAILSUBJECT = "Your new account '%USERNAME'";
	    $EMAILSUBJECT = ReplaceText($EMAILSUBJECT,"%USERNAME",$username);

	    $body = readmail("mail_register.txt");
	    $body = ReplaceText($body,"%USERNAME",$username);
	    $body = ReplaceText($body,"%UID",$uid);
	    $body = ReplaceText($body,"%EMAIL",$email);
	    $body = ReplaceText($body,"%ACTIVATION",$activation);
	    $body = ReplaceText($body,"%IPADDRESS",$ip);
	    $body = ReplaceText($body,"%BASEURL",$BASEURL);

	    $headers .= $CONST_EMAILHEADER;

	    //error_reporting (E_ERROR);
	    error_reporting (E_ERROR | E_WARNING | E_PARSE); // This will NOT report uninitialized variables
	    $backvalue =  mail($email, $EMAILSUBJECT, $body,$headers);
	    error_reporting (E_ERROR | E_WARNING | E_PARSE); // This will NOT report uninitialized variables
    }

    return $backvalue;
  }

 //--------------------------------------------------------------

  function sendEmailUpdatePWD($uid, $username, $activation, $ip) {
    global $CONST_EMAILHEADER;
    global $BASEURL;

    $email = getEmail($uid);
    $backvalue = false;

    if ($email) {
	    $EMAILSUBJECT = "Password change for account '%USERNAME'";
	    $EMAILSUBJECT = ReplaceText($EMAILSUBJECT,"%USERNAME",$username);

	    $body = readmail("mail_updatepwd.txt");
	    $body = ReplaceText($body,"%USERNAME",$username);
	    $body = ReplaceText($body,"%UID",$uid);
	    $body = ReplaceText($body,"%EMAIL",$email);
	    $body = ReplaceText($body,"%ACTIVATION",$activation);
	    $body = ReplaceText($body,"%IPADDRESS",$ip);
	    $body = ReplaceText($body,"%BASEURL",$BASEURL);

	    $headers .= $CONST_EMAILHEADER;

	    //error_reporting (E_ERROR);
	    error_reporting (E_ERROR | E_WARNING | E_PARSE); // This will NOT report uninitialized variables
	    $backvalue =  mail($email, $EMAILSUBJECT, $body,$headers);
	    error_reporting (E_ERROR | E_WARNING | E_PARSE); // This will NOT report uninitialized variables
    }

    return $backvalue;
  }

 //--------------------------------------------------------------

  function sendEmailResetPWD($uid, $username, $pwd, $activation, $ip) {
    global $CONST_EMAILHEADER;
	global $BASEURL;

    $email = getEmail($uid);
    $backvalue = false;

    if ($email) {
	    $EMAILSUBJECT = "Password reset for account '%USERNAME'";
	    $EMAILSUBJECT = ReplaceText($EMAILSUBJECT,"%USERNAME",$username);

	    $body = readmail("mail_resetpwd.txt");
	    $body = ReplaceText($body,"%USERNAME",$username);
	    $body = ReplaceText($body,"%UID",$uid);
	    $body = ReplaceText($body,"%EMAIL",$email);
	    $body = ReplaceText($body,"%ACTIVATION",$activation);
	    $body = ReplaceText($body,"%IPADDRESS",$ip);
	    $body = ReplaceText($body,"%PASSWORD",$pwd);
	    $body = ReplaceText($body,"%BASEURL",$BASEURL);

	    $headers .= $CONST_EMAILHEADER;

	    //error_reporting (E_ERROR);
	    error_reporting (E_ERROR | E_WARNING | E_PARSE); // This will NOT report uninitialized variables
	    $backvalue =  mail($email, $EMAILSUBJECT, $body,$headers);
	    error_reporting (E_ERROR | E_WARNING | E_PARSE); // This will NOT report uninitialized variables
    }

    return $backvalue;
  }



  //--------------------------------------------------------------

    // mod
    //0 = pwderr
    //1 = device
    //2 = country

    function sendSecurityWarning($uid, $mod, $country, $oldcountry, $device) {
      global $CONST_EMAILHEADER;
      global $BASEURL;
      global $ipaddress;

      $email = getEmail($uid);
      $backvalue = false;
      $username = getUsername($uid);

      if ($email) {
  	    $EMAILSUBJECT = "SECURITY ALERT '%USERNAME'";
  	    $EMAILSUBJECT = ReplaceText($EMAILSUBJECT,"%USERNAME",$username);

		$body = "";
		if ($mod == 0) {
	  	    $body = readmail("mail_attentionpwderr.txt");
		}
		else if ($mod == 1) {
	  	    $body = readmail("mail_attentiondevice.txt");
		}
		else if ($mod == 2) {
	  	    $body = readmail("mail_attentioncountry.txt");
		}
		else {
			return false;
		}
  	    $body = ReplaceText($body,"%USERNAME",$username);
  	    $body = ReplaceText($body,"%UID",$uid);
  	    $body = ReplaceText($body,"%EMAIL",$email);
  	    $body = ReplaceText($body,"%IPADDRESS",$ipaddress);
  	    if ($country != "") {
	  	    $body = ReplaceText($body,"%COUNTRY",$country);
  	    }
  	    if ($oldcountry != "") {
	  	    $body = ReplaceText($body,"%OLDCOUNTRY",$oldcountry);
  	    }
  	    if ($device != "") {
	  	    $body = ReplaceText($body,"%DEVICE",$device);
  	    }
  	    $body = ReplaceText($body,"%BASEURL",$BASEURL);

  	    $headers .= $CONST_EMAILHEADER;

  	    //error_reporting (E_ERROR);
  	    error_reporting (E_ERROR | E_WARNING | E_PARSE); // This will NOT report uninitialized variables
  	    $backvalue =  mail($email, $EMAILSUBJECT, $body,$headers);
  	    error_reporting (E_ERROR | E_WARNING | E_PARSE); // This will NOT report uninitialized variables
      }

      return $backvalue;
    }

  //--------------------------------------------------------------

  function updatePwd($uid, $val, $ip) {
	  $uid = intval($uid);
      $newpwd = md5($val);
      $query = "UPDATE users SET pwdchange = '".$newpwd."' WHERE uid = '".$uid."'";
      $result = mysql_query($query);
      if ($result) {
	    $activation = getActivation($uid);
		$user = getUsername($uid);
		sendEmailUpdatePWD($uid, $user, $activation, $ip);
		return true;
      } else {
      	 return false;
      }
  }

  //--------------------------------------------------------------

  function resetPwd($uid, $ip) {
	  $uid = intval($uid);
  	  $val = getRND(5);
      $newpwd = md5($val);
      $query = "UPDATE users SET pwdchange = '".$newpwd."' WHERE uid = '".$uid."'";
      $result = mysql_query($query);
      if ($result) {
	    $activation = getActivation($uid);
		$user = getUsername($uid);
		sendEmailResetPWD($uid, $user, $val, $activation, $ip);
		return true;
      } else {
      	 return false;
      }
  }

  //--------------------------------------------------------------

  function isValidUser($hostuid) {
 	$hostuid = intval($hostuid);
  	if ($hostuid == 0) {
  		return true;
  	}
       $query = "SELECT username FROM users WHERE uid = '".$hostuid."'";

       $result = mysql_query($query);
 	   if (mysql_num_rows($result) > 0) {
 	   		return true;
 	   }
 	   return false;
  }

  //--------------------------------------------------------------

 function isSender($uid, $mid) {
  	$uid = intval($uid);
  	$mid = intval($mid);

 	$query = "SELECT fromuid FROM `messages` WHERE `mid` = ".$mid." AND `fromuid` = ".$uid;
 	//printf($query."<BR>");
    $result = mysql_query($query);
    if (mysql_num_rows($result) > 0) {
        return true;
    }
    return false;
 }


 //--------------------------------------------------------------

 function sendText($uid, $host, $textutf8, $created) {
 	$uid = intval($uid);
 	$host = intval($host);

    $sentTimeStamp = date("U")."000";
 	$backvalue = "-1";
 	// It seems we do not have to convert with POST messages
 	//$textiso = utf8_decode($textutf8);
	$textiso = $textutf8;

    if (!isValidUser($host)) {
    	// fake valid user response but do not enter this into the DB!
        return $backvalue = "1#".$sentTimeStamp."#0"; // mid 0 == there is no new mid because this is a pseudomessage
    }

 	if (substr($textiso, 0,1) == "F") {
 		 	// FAILED INFO UPDATE
 	 	 	// the client tells us that he could not decrypt the message
 			$mid = substr($textiso, 1);
			flagfailed($uid, $host, $mid);
	        return $backvalue = "1#".$sentTimeStamp."#0"; // mid 0 == there is no new mid because this is a pseudomessage
 	}
 	if (substr($textiso, 0,1) == "R") {
 		 	// READ INFO UPDATE
 	 	 	// the client tells us that he has read everything from the host up to the mid which is the text
 	 	 	$val = substr($textiso, 1);
			confirmread($uid, $host, $val);
	        return $backvalue = "1#".$sentTimeStamp."#0"; // mid 0 == there is no new mid because this is a pseudomessage
 	}
 	if (substr($textiso, 0,1) == "A") { // A == abort request
 			// REVOKE REQUEST
 			$mid = substr($textiso, 1);
 			// first check if allowed to revoke ($uid is the sender!)
 			if (isSender($uid, $mid)) {
	 			revoke($uid, $mid);
 			}
	        return $backvalue = "1#".$sentTimeStamp."#0"; // mid 0 == there is no new mid because this is a pseudomessage
 	}


 	if (substr($textiso, 0,1) == "U") {
 	    $textiso = str_replace("\n", "@@@NEWLINE@@@", $textiso);
 	}

    $query = "INSERT INTO messages (fromuid, touid, text, created, sent)
               VALUES ('".$uid."','".$host."','".$textiso."','".$created."','".$sentTimeStamp."')";
    //printf("#0b ".$query." <BR>");
    $result = mysql_query($query);
    //printf("#0c <BR>");
    if ($result) {
       //printf("#1<BR>");
       $query2 = "SELECT mid FROM messages WHERE sent = '".$sentTimeStamp."' AND text = '".$textiso."' ORDER BY mid DESC";
       $result2 = mysql_query($query2);
       //printf("#0b ".$query2." <BR>");
       //printf("#2<BR>");
	   if (mysql_num_rows($result2) > 0) {
	       //printf("#3<BR>");
	       $row = mysql_fetch_array($result2,MYSQL_ASSOC);
	       $e = implode(" ",$row);
	       $f = explode(" ",$e);
	       $backvalue = "1#".$sentTimeStamp."#".$f[0];
	       //printf("#4<BR>");
	   }
    } else {
    	 return -1;
    }
    return $backvalue;
 }

  //--------------------------------------------------------------

  function getReceipientOfMid($mid) {
	   $mid = intval($mid);
       $query2 = "SELECT touid FROM messages WHERE mid = '".$mid."'";

       $result2 = mysql_query($query2);
 	   if (mysql_num_rows($result2) > 0) {
 	       $row = mysql_fetch_array($result2,MYSQL_ASSOC);
 	       $e = implode(" ",$row);
 	       $f = explode(" ",$e);

 	       return $f[0];
 	   }
 	   return -1;
  }

  //--------------------------------------------------------------

  function getSenderOfMid($mid) {
	   $mid = intval($mid);
       $query2 = "SELECT fromuid FROM messages WHERE mid = '".$mid."'";

       $result2 = mysql_query($query2);
 	   if (mysql_num_rows($result2) > 0) {
 	       $row = mysql_fetch_array($result2,MYSQL_ASSOC);
 	       $e = implode(" ",$row);
 	       $f = explode(" ",$e);

 	       return $f[0];
 	   }
 	   return -1;
  }

  //--------------------------------------------------------------

  function revoke($uid, $mid) {
	   $uid = intval($uid);
	   $mid = intval($mid);
  	   global $REVOKEDTEXT;
       $backvalue = false;
       $revokeTimeStamp = date("U")."000";
       $query1 = "UPDATE messages SET revoked = '".$revokeTimeStamp."' WHERE fromuid = '".$uid."' AND mid = '".$mid."'";
       $query2 = "UPDATE messages SET text = '".$REVOKEDTEXT."' WHERE fromuid = '".$uid."' AND mid = '".$mid."'";
       // Now automatically create a revoke message"W+MID" e,g W1234 as text where 1234 is the MID to revoke locally
       sendText($uid, getReceipientOfMid($mid), "W".$mid, $revokeTimeStamp); // revoke the message at the receipient
       sendText(getReceipientOfMid($mid), $uid, "W".$mid, $revokeTimeStamp); // revoke the message at the sender also! (fake it to be from the original receipient)
       if (mysql_query($query1) && mysql_query($query2)) {
 	       $backvalue = true;
 	   }
 	   return $backvalue;
  }

  //--------------------------------------------------------------

 function receive($uid, $mid) {
	   $uid = intval($uid);
	   $mid = intval($mid);
 	   global $REVOKEDTEXT;

  	   $largestServerMid = getLargestMidServer();
  	   if ($mid > $largestServerMid) {
  	        return "2#". $largestServerMid;
 	   }

	    $receivedTimeStamp = date("U")."000";
        $query2 = "SELECT mid, fromuid, text, created, sent, received FROM messages WHERE mid > '".$mid."' AND touid = '".$uid."' AND `text` != '".$REVOKEDTEXT."' ORDER BY mid ASC";

        if($mid == -1) {
        		// if -1 is sent, then we expect only to get the latest MID of the database as a return value!!!
				// -1 should only be sent for a fresh, new database or if there are no users in our
				// list.
		        $query2 = "SELECT mid, fromuid, touid, text, created, sent, received FROM messages WHERE mid > '".$mid."' AND touid = '".$uid."' ORDER BY mid DESC";
        }

        $result2 = mysql_query($query2);
        //printf("#0b ".$query2." <BR>");
        //printf("#2<BR>");
 	   if (mysql_num_rows($result2) > 0) {
 	       //printf("#3<BR>");
 	       $row = mysql_fetch_array($result2,MYSQL_ASSOC);
 	       $e = implode(" ",$row);
 	       $f = explode(" ",$e);

 	       $text = $f[2];
 	       $backvalue = "1#".$f[0]."#".encUid($uid,$f[1])."#".$f[3]."#".$f[4]."#".$text;

		   if ((is_null($f[5]) || $f[5] == "")) {
			   // do not do this for revoked messages! we want to track if the message was revoked BEFORE it was received or after!
			   if ($text != $REVOKEDTEXT) {
		 	       // save that we have received the message (IF NOT YET)
		 	       $newmid = $f[0];
			       $query = "UPDATE messages SET received = '".$receivedTimeStamp."' WHERE mid = '".$newmid."'";
		 	       mysql_query($query);
			   }
 	       }
 	       if (substr($f[2],0,1) == "K") {
 	       		// This was a key message, remove the text!
		       $query = "UPDATE messages SET text = 'U[ outdated session key ]' WHERE mid = '".$newmid."'";
	 	       mysql_query($query);
 	       }

 	   }
 	   else {
 	      $backvalue = "0";
 	   }
    return $backvalue;
 }


  //--------------------------------------------------------------

  function getLargestMidServer() {
       $query = "SELECT MAX(mid) FROM messages";

       $result = mysql_query($query);
        //printf("#0b ".$query2." <BR>");
        //printf("#2<BR>");
 	   if (mysql_num_rows($result) > 0) {
 	       //printf("#3<BR>");
 	       $row = mysql_fetch_array($result,MYSQL_ASSOC);
 	       $e = implode(" ",$row);
 	       $f = explode(" ",$e);
 	       if ($f[0] == "") {
 	           return 0;
 	       }
 	       return $f[0];
 	   }
 	   return 0;
  }

  //--------------------------------------------------------------

 // have will also return received and read messag mid@timestamp separated by #

 function have($uid, $val) {
	  $uid = intval($uid);
     $values = explode("#", $val);
     if (count($values) == 3) {
 	   $mid = $values[0];
	   $mid = intval($mid);
 	   $tsreceived = $values[1];
 	   $tsread = $values[2];

 	   $largestServerMid = getLargestMidServer();
 	   if ($mid > $largestServerMid) {
 	        return "2#". $largestServerMid;
	   }
	   $receivedTimeStamp = date("U")."000";
       $query2 = "SELECT mid, fromuid, touid, text, created, sent, received FROM messages WHERE mid > '".$mid."' AND touid = '".$uid."' ORDER BY mid ASC";
       $result2 = mysql_query($query2);
  	   if (mysql_num_rows($result2) > 0) {
 	       $backvalue = "1##".inforeceived($uid, $tsreceived)."##".inforead($uid, $tsread);
 	   }
 	   else {
 	       $backvalue = "0##".inforeceived($uid, $tsreceived)."##".inforead($uid, $tsread);
 	   }
       return $backvalue;
 	 }
 	 return "0##0##0";
 }

 //--------------------------------------------------------------

 function flagfailed($uid, $host, $mid) {
	$uid = intval($uid);
	$host = intval($host);
	$mid = intval($mid);
    $backvalue = "-1";
    $query = "UPDATE `messages` SET `failed` = '1' WHERE fromuid = '".$host."' AND touid = '".$uid."' AND `mid` = '".$mid."'";
    //printf($query."<BR>");
    if (mysql_query($query)) {
	    	$backvalue = "1";
    }
    return $backvalue;
 }


 //--------------------------------------------------------------

 function confirmread($uid, $host, $val) {
    global $REVOKEDTEXT;

	$uid = intval($uid);
	$host = intval($host);
    $backvalue = "-1";
	$readTimeStamp = date("U")."000";
    $query = "UPDATE `messages` SET `read` = '".$readTimeStamp."' WHERE fromuid = '".$host."' AND touid = '".$uid."' AND `read` = '' AND  mid <= '".$val."' AND `text` != '".$REVOKEDTEXT."'";
    //printf($query."<BR>");
    if (mysql_query($query)) {
    	$backvalue = "1";
    }
    return $backvalue;
 }

  //--------------------------------------------------------------

 // inforead will ALSO return FAILED messages, therefore if failed == 1 then the timestamp is set to be negative!
 // the client has to interpret negative read timestamps as failed to decrypt

 function inforead($uid, $tsread) {
   	   $uid = intval($uid);
 	   $backvalue = "";
	   $receivedTimeStamp = date("U")."000";
       $query2 = "SELECT `mid`, `read`, `failed`, `touid` FROM `messages` WHERE `read` > '".$tsread."' AND `fromuid` = '".$uid."' ORDER BY mid ASC";
       //printf($query2."<BR>");
       $result2 = mysql_query($query2);
        $found = false;
 	   if (mysql_num_rows($result2) > 0) {
  	        $found = true;
 	   		$backvalue = "1";
 	   		while($row = mysql_fetch_array($result2,MYSQL_ASSOC)) {
	 	       $e = implode(" ",$row);
	 	       $f = explode(" ",$e);

	 	       // Only getting received informations if the other user has confirmed added us to his list!
			   $hostuid = $f[3];
			   if (isAllowedToGet($uid, $hostuid)) {
		 	       if ($f[2] == 1) {
		 	         	// failed => set timestamp to negative value
			 	       $backvalue .= "#".$f[0]."@-".$f[1];
		 	       } else {
		 	       	 	// everything ok
			 	       $backvalue .= "#".$f[0]."@".$f[1];
		 	       }
   	 	       }
	    	}
 	   }
  	   if ($found) {
  	      $backvalue = "1".$backvalue;
  	   }
  	   else {
  	      $backvalue = "0";
  	   }
 	   return $backvalue;
 }


  function inforeceived($uid, $tsreceived) {
   	    $uid = intval($uid);
  	    $receivedTimeStamp = date("U")."000";
        $query2 = "SELECT mid, received, `toid` FROM messages WHERE received > '".$tsreceived."' AND fromuid = '".$uid."' ORDER BY mid ASC";
        $result2 = mysql_query($query2);
        $found = false;
        $backvalue = "";
  	   if (mysql_num_rows($result2) > 0) {
  	        $found = true;
 	        //printf($query2."<BR>");
  	   		while($row = mysql_fetch_array($result2,MYSQL_ASSOC)) {
 	 	       $e = implode(" ",$row);
 	 	       $f = explode(" ",$e);

 	 	       // Only getting received informations if the other user has confirmed added us to his list!
 	 	       $hostuid = $f[2];
 	 	       if (isAllowedToGet($uid, $hostuid)) {
		 	       $backvalue .= "#".$f[0]."@".$f[1];
 	 	       }
 	    	}
  	   }
  	   if ($found) {
  	      $backvalue = "1".$backvalue;
  	   }
  	   else {
  	      $backvalue = "0";
  	   }
 	   return $backvalue;
  }


  //--------------------------------------------------------------
  //--------------------------------------------------------------

  function deleteUserlist($uid, $manual) {
	$uid = intval($uid);
    $bak = "";
    if ($manual) {
    	$bak = "bak";
    }
    $query = "DELETE FROM `userlist".$bak."` WHERE uid = '".$uid."'";
    $result = mysql_query($query);
    if ($result) {
          return true;
    }
    return false;
  }

  function backupUserlist($uid, $val, $manual) {
	$uid = intval($uid);
    $result1 = deleteUserlist($uid, $manual);
    if ($val == "") {
    	// just clear do not add anybody
        $backvalue = "1";
    	return $backvalue;
    }

 	$backvalue = "-1";
 	$hostuids = explode("#", $val);
 	$result2 = true;
    $bak = "";
    if ($manual) {
    	$bak = "bak";
    }
	foreach ($hostuids as $hostuidenc) {
	    $hostuid = decUid($uid, $hostuidenc);
	    if ($hostuid != -1) {
			$query = "INSERT INTO `userlist".$bak."` (`uid`, `hostuid`)
		               VALUES ('".$uid."','".$hostuid."')";
		    $result2 = $result2 && mysql_query($query);
	    //} else {
	    // 	// Cannot decrypt a UID, backup failed
	    //    $result2 = false;
	    }
	}
    if ($result1 && $result2) {
          $backvalue = "1";
    }
 	else {
 	      $backvalue = "0";
 	}
    return $backvalue;
  }

  function restoreUserlist($uid, $manual) {
	   $uid = intval($uid);
       $bak = "";
       if ($manual) {
       	$bak= "bak";
       }
       $backvalue = "";
       $query = "SELECT hostuid FROM `userlist".$bak."` WHERE uid = '".$uid."'";
       $result = mysql_query($query);
       $found = false;
 	   if (mysql_num_rows($result) > 0) {
 	   		while($row = mysql_fetch_array($result,MYSQL_ASSOC)) {
	 	       $e = implode(" ",$row);
	 	       $f = explode(" ",$e);
	 	       if ($backvalue != "") {
		 	       $backvalue .= "#";
	 	       }
	 	       $backvalue .= $f[0];
	    	}
  	       $backvalue = "1#".encText($uid, $backvalue);
 	   }
 	   else {
 	      $backvalue = "0";
 	   }
	   return $backvalue;
  }

  function updatePhone($uid, $val) {
	$uid = intval($uid);
 	$backvalue = "-1";
 	if ($val == "delete") {
 	 	$val = "";
 	}
    $query = "UPDATE `users` SET `phone` = '".$val."' WHERE uid = '".$uid."'";
    $result = mysql_query($query);
    if ($result) {
          $backvalue = "1";
    }
 	else {
 	      $backvalue = "0";
 	}
    return $backvalue;
  }


  function getPhone($uid, $hostuid) {
	   $uid = intval($uid);
	   $hostuid = intval($hostuid);
 	   if (isAllowedToGet($uid, $hostuid)) {
 	   			// we are allowed to receive the phone number from user hostuid, because user hostuid has us (uid) in his userlist
		       $query2 = "SELECT phone FROM `users` WHERE uid = '".$hostuid."'";
		       $result2 = mysql_query($query2);
		 	   if (mysql_num_rows($result2) > 0) {
		 	       $row = mysql_fetch_array($result2,MYSQL_ASSOC);
		 	       $e = implode(" ",$row);
		 	       $f = explode(" ",$e);
		 	       return $f[0];
		 	   }
 	   }
 	   return "-1";
  }


 function hasPhone($uid, $val) {
	$uid = intval($uid);
    $backvalue = "";
    $hostuids = explode("#", $val);
    $found = false;
    foreach ($hostuids as $hostuid) {
       $found = true;
       if ((strlen($backvalue)) > 0) {
 	       $backvalue .= "#";
       }
       $hostuid = decUid($uid, $hostuid);
       $nextNumber = getPhone($uid, $hostuid);
       if ($nextNumber != "-1") {
       		$nextNumber = encText($uid, $nextNumber);
       }
       $backvalue .= $nextNumber;
	}
	if ($found) {
	    return "1#".$backvalue;
	} else {
	    return "-1";
	}
 }


  //--------------------------------------------------------------
  //--------------------------------------------------------------

  function updateAvatar($uid, $val) {
	$uid = intval($uid);
 	$backvalue = "-1";
 	if ($val == "delete") {
 	 	$val = "";
 	}
    $query = "UPDATE `users` SET `avatar` = '".$val."' WHERE uid = '".$uid."'";
    $result = mysql_query($query);
    if ($result) {
          $backvalue = "1";
    }
 	else {
 	      $backvalue = "0";
 	}
    return $backvalue;
  }


  function isAllowedToGet($uid, $hostuid) {
	   $uid = intval($uid);
	   $hostuid = intval($hostuid);
       $query1 = "SELECT hostuid FROM `userlist` WHERE uid = '".$hostuid."' AND hostuid = '".$uid."'";
       //printf($query1."<BR>");
       $result1 = mysql_query($query1);
 	   if (mysql_num_rows($result1) > 0) {
   			// we are allowed to receive username/avatar/phonenumber  from user hostuid, because user hostuid has us (uid) in his userlist
 	   		return true;
 	   }
 	   return false;
  }

  function getAvatar($uid, $hostuid) {
	   $uid = intval($uid);
	   $hostuid = intval($hostuid);
 	   if (isAllowedToGet($uid, $hostuid)) {
 	   			// we are allowed to receive the avatar  from user hostuid, because user hostuid has us (uid) in his userlist
		       $query2 = "SELECT `avatar` FROM `users` WHERE uid = '".$hostuid."'";
		       $result2 = mysql_query($query2);
		 	   if (mysql_num_rows($result2) > 0) {
		 	       $row = mysql_fetch_array($result2,MYSQL_ASSOC);
		 	       $e = implode(" ",$row);
		 	       $f = explode(" ",$e);
		 	       return $f[0];
		 	   }
 	   }
 	   return "-1";
  }


 function hasAvatar($uid, $val) {
	$uid = intval($uid);
    $backvalue = "";
    $hostuids = explode("#", $val);
    $found = false;
    foreach ($hostuids as $hostuid) {
       $found = true;
       if ((strlen($backvalue)) > 0) {
 	       $backvalue .= "#";
       }
       $hostuid = decUid($uid, $hostuid);
       $nextAvatar = getAvatar($uid, $hostuid);
       //if ($nextAvatar != "-1") {
       //		$nextAvatar = encLongText($uid, $nextAvatar);
       //}
       $backvalue .= $nextAvatar;
	}
	if ($found) {
	    return "1#".$backvalue;
	} else {
	    return "-1";
	}
 }


  //--------------------------------------------------------------
  //--------------------------------------------------------------

 function sendkey($uid, $key) {
	$uid = intval($uid);
 	// first delete previous keys
 	clearkey($uid);
 	$result = false;

 	if ($uid != -1) {
	 	$backvalue = "";
	 	$keyiso = utf8_decode($key);
	  	$createdTimeStamp = date("U")."000";
		$query = "INSERT INTO `keys` (`uid`, `pubkey`, `created`)
               VALUES ('".$uid."','".$keyiso."','".$createdTimeStamp."')";

		//printf($query."<BR>");
	    $result = mysql_query($query);
 	}

    if ($result) {
          $backvalue = "1";
    }
 	else {
 	      $backvalue = "0";
 	}
    return $backvalue;
 }

   //--------------------------------------------------------------

 function clearkey($uid) {
	$uid = intval($uid);
    $backvalue = "";
    $query = "DELETE FROM `keys` WHERE uid = '".$uid."'";
    $result = mysql_query($query);
    if ($result) {
          $backvalue = "1";
    }
    else {
 	      $backvalue = "0";
    }
    return $backvalue;
 }

   //--------------------------------------------------------------

 function getkey($uid) {
	   $uid = intval($uid);
       $backvalue = "";
       $query2 = "SELECT pubkey, created FROM `keys` WHERE uid = '".$uid."' ORDER BY kid DESC";
       $result2 = mysql_query($query2);
 	   if (mysql_num_rows($result2) > 0) {
 	       $row = mysql_fetch_array($result2,MYSQL_ASSOC);
 	       $e = implode(" ",$row);
 	       $f = explode(" ",$e);
 	       $backvalue = "1#".$f[1]."#".$f[0];
 	   }
 	   else {
 	      $backvalue = "0";
 	   }
       return $backvalue;
 }

   //--------------------------------------------------------------

 function haskey($uid, $val) {
	$uid = intval($uid);
    $backvalue = "";
    $uids = explode("#", $val);
    foreach ($uids as $hostuid) {
       $hostuid = decUid($uid, $hostuid);
  	   $hostuid = intval($hostuid);
       if ((strlen($backvalue)) > 0) {
 	       $backvalue .= "#";
       }
       if (!isAllowedToGet($uid, $hostuid)) {
 	       $backvalue .= "0";
       } else {
       	   // We are allowed to download the key
	       $query2 = "SELECT created FROM `keys` WHERE uid = '".$hostuid."' ORDER BY kid DESC";
	       $result2 = mysql_query($query2);
	 	   if (mysql_num_rows($result2) > 0) {
	 	       $row = mysql_fetch_array($result2,MYSQL_ASSOC);
	 	       $e = implode(" ",$row);
	 	       $f = explode(" ",$e);
	 	       $backvalue .= $f[0];
	 	   } else {
	 	       $backvalue .= "0";
	 	   }
       }
	}
    return "1#".$backvalue;
 }

   //--------------------------------------------------------------
   //--------------------------------------------------------------

 function showMessage($text) {
	printf("-");
	require('info.php');
    exit;
 }

   //--------------------------------------------------------------

   function formatuser($user) {
     $user = trim($user);
     $vgluser = strtolower($user);
     if ($vgluser == "system") {
        return "!not valid!";
     }
     if ($vgluser == "admin") {
        return "!not valid!";
     }
     if ($vgluser == "root") {
        return "!not valid!";
     }
     if ($vgluser == "delphino") {
        return "!not valid!";
     }
     $zeichenkette = "";
     for($i=0;$i<strlen($user);$i++) {
        $zeichen = substr($user,$i,1);
        if ($zeichen != " ") {
           $ascii = ord($zeichen);

           $ok = false;
           if (($ascii >= 48)&&($ascii <= 57)) $ok = true;   //Zahl
           if (($ascii >= 65)&&($ascii <= 90)) $ok = true;   //GROSSE buschstaben
           if (($ascii >= 97)&&($ascii <= 122)) $ok = true;  //kleine buschstaben
           if (($ascii == 95)||($ascii == 45)) $ok = true; // "_" imd "-"
           if ($zeichen == ".") $ok = true;

           if ($zeichen == urlencode($zeichen) && $ok) {
              $zeichenkette = "$zeichenkette$zeichen";
           }//end if
        }//end if
     }//next i

     return $zeichenkette;
   }



  //--------------------------------------------------------------
  //--------------------------------------------------------------

 function prepareSimpleKey($uid) {
	 // get offset and secret from newest session if this user
	 $result = mysql_query("SELECT secret,offset FROM sessions WHERE uid = '".$uid."' ORDER BY created DESC");
	 if (mysql_num_rows($result) > 0) {
	 		       $row = mysql_fetch_array($result,MYSQL_ASSOC);
			       $e = implode(" ",$row);
			       $f = explode(" ",$e);
			       $secret = $f[0];
			       $secret = substr($secret,5); // only use 15 remaining characters of the secret
			       $offset = $f[1];
			       $servertime = date("U");

			       // now state estimation for usertime
			       $estimatedusertime = $servertime - $offset;
			       $fragmentestimatedusertime = floor($estimatedusertime/100);
			       $fragmentestimatedusertime = md5($fragmentestimatedusertime);
			       $secret = md5($secret);

				   $simpleKey = array();
				   $simpleKey[0] = ord($fragmentestimatedusertime[0]);
				   $simpleKey[1] = ord($secret[0]);
				   $simpleKey[2] = ord($fragmentestimatedusertime[1]);
				   $simpleKey[3] = ord($secret[1]);
				   $simpleKey[4] = ord($fragmentestimatedusertime[2]);
				   $simpleKey[5] = ord($secret[2]);
				   $simpleKey[6] = ord($fragmentestimatedusertime[3]);
				   $simpleKey[7] = ord($secret[3]);
		  	       return $simpleKey;
     }
     printf("ERROR: NO SIMPLE KEY FOR UID ".$uid." FOUND!<BR>");
     return array();
 }

   //--------------------------------------------------------------


   function encUid($uid, $ptext) {
   			//printf("encUid<BR>");
  			//printf("ptext:".$ptext."<BR>");
   			$simpleKey = prepareSimpleKey($uid);
   			$addon = (1*$simpleKey[0] + 1 * $simpleKey[1] + 10*$simpleKey[2]+ 10*$simpleKey[3] + 100*$simpleKey[4]+ 100*$simpleKey[5] + 1000*$simpleKey[6]+ 1000*$simpleKey[7]);
  			//printf("addon:".$addon."<BR>");
   			$encoded = $ptext + $addon;
  			//printf("encoded:".$encoded."<BR>");
   			//printf("md5(ptext):".md5($ptext)."<BR>");
   			//printf("substr1(md5()):".substr(md5($ptext),0,1)."<BR>");

   			return (substr(md5($ptext),0,1).$encoded);
   }

   //--------------------------------------------------------------

   function decUid($uid, $etext) {
   			//printf("decUid<BR>");
   			//printf($etext."<BR>");
   			$simpleKey = prepareSimpleKey($uid);
   			$checkbyte = substr($etext, 0, 1);
   			$etext = substr($etext, 1);
   			//printf($checkbyte."<BR>");
   			//printf($text."<BR>");
   			$addon = (1*$simpleKey[0] + 1 * $simpleKey[1] + 10*$simpleKey[2]+ 10*$simpleKey[3] + 100*$simpleKey[4]+ 100*$simpleKey[5] + 1000*$simpleKey[6]+ 1000*$simpleKey[7]);
  			//printf("addon:".$addon."<BR>");
   			$decoded = $etext - $addon;
   			//printf($decoded."<BR>");
   			if ($checkbyte == substr(md5($decoded),0,1)) {
   				return $decoded;
   			}
   			return -10;
   }

   // --------------------------------------------------------

 function prepareKey($uid) {
	 // get offset and secret from newest session if this user
	 $result = mysql_query("SELECT secret,offset FROM sessions WHERE uid = '".$uid."' ORDER BY created DESC");
	 if (mysql_num_rows($result) > 0) {
	 		       $row = mysql_fetch_array($result,MYSQL_ASSOC);
			       $e = implode(" ",$row);
			       $f = explode(" ",$e);
			       $secret = $f[0];
			       $secret = substr($secret,5); // only use 15 remaining characters of the secret
			       $offset = $f[1];
			       $servertime = date("U");

			       // now state estimation for usertime
			       $estimatedusertime = $servertime - $offset;
			       $fragmentestimatedusertime = floor($estimatedusertime/100);
			       $fragmentestimatedusertime = md5($fragmentestimatedusertime);
			       $secret = md5($secret);

				   $entrcypted = array();
		  	       for ($i = 0; $i < 32; $i++) {
		  	       		$secretE = ord($secret[$i]);
		  	       		$timeE = ord($fragmentestimatedusertime[$i]);
		  	            $nextByte = $secretE ^ $timeE;
		  	            $entrcypted[$i] = $nextByte;
		  	       }
		  	       return $entrcypted;
     }
     printf("ERROR: NO KEY FOR UID ".$uid." FOUND!<BR>");
     return array();
   }

   //--------------------------------------------------------------

   function encLongText($uid, $decText) {
      //printf($decText."<BR>");
      $encodedText = "";
      $chunks = ceil(strlen($decText) / 30);
      //printf($chunks."<BR>");
      for ($c = 0; $c < $chunks; $c++) {
          $chunk = substr($decText, $c * 30);
          if (strlen($chunk) > 30) {
             $chunk = substr($chunk, 0, 30);
          }
          //printf($chunk."<BR>");
          $encChunk = encText($uid, $chunk);
          if ($encodedText != "") {
          	$encodedText = $encodedText.";";
          }
          $encodedText .= $encChunk;
      }
      return $encodedText;
   }


   function encText($uid, $text) {
         $key = prepareKey($uid);
         $pad = count($key) - strlen($text) - 2;
         if ($pad < 0) {
            $pad = 0;
         }
         $index = rand (0, $pad);
         $rnd = getRND($pad);
         $paddedString = substr($rnd, 0, $index) ."#" . $text . "#" . substr($rnd, $index);

         //printf("padded [".$pad.", ".$index."]: ".$paddedString."<BR>");

         $encText = "";
		 for ($i = 0; $i < 32; $i++) {
		 	$paddedStringE = ord($paddedString[$i]);
		 	$keyE = $key[$i];
		 	$nextByte = $paddedStringE ^ $keyE;
		  	$encText .= chr($nextByte);
		 }
 	     $encTextBase64 = base64_encode($encText);
	     return ($encTextBase64);
   }

   //--------------------------------------------------------------

   function decLongText($uid, $encLongText) {
        $encChunks = explode(";", $encLongText);
        $decText = "";
	    foreach ($encChunks as $encChunk) {
	    	$chunk = decText($uid, $encChunk);
	    	if ($chunk = -1) {
	    		return -1;
	    	}
	    	$decText .= $chunk;
		}
		return $decText;
   }


   function decText($uid, $encTextBase64) {
       $encText = base64_decode($encTextBase64);
       $key = prepareKey($uid);
       $ptext = "";
	   for ($i = 0; $i < 32; $i++) {
		 	$encTextE = ord($encText[$i]);
		 	$keyE = $key[$i];
		 	$nextByte = $keyE ^ $encTextE;
		  	$ptext .= chr($nextByte);
	   }
	   $i1 = strpos($ptext, "#");
	   $i2 = strpos($ptext, "#", $i1+1);
	   //printf($ptext.",".$i1.",".$i2."<BR>");
	   if ($i2 != null && $i1 >= 0 && $i2 >= 0) {
	   		return substr($ptext, $i1+1, $i2-$i1-1);
	   }
	   return -1;
   }



  //--------------------------------------------------------------
  //--------------------------------------------------------------
  //--------------------------------------------------------------
  //--------------------------------------------------------------

// $activation = "1234567";
// $uid
// printf(sendEmail($uid, $user, $activation, $ip));
// exit;


 if ($cmd == "create") {
 	if (!$allownewaccounts) {
    	printf("-17"); // currently no new accounts allowed on this server
	    exit;
 	}

    //printf("user:".$user."<BR>");
	//printf("pwd:".$pwd."<BR>");
	//printf("email:".$email."<BR><BR>");

    $user = base64_decode($user);
    $user = serverDec($user);
    $pwd = base64_decode($pwd);
    $pwd = serverDec($pwd);
    $email = base64_decode($email);
    $email = serverDec($email);

    //printf("user:".$user."<BR>");
	//printf("pwd:".$pwd."<BR>");
	//printf("email:".$email."<BR><BR>");


    $user = formatuser($user);
    if ($user == "!not valid!") {
       $user = "user";
    }
    $vglpwd = formatuser($pwd);
    if (isRegistered($email)) {
    	printf("-2"); // -2 == email already registered
	    exit;
    }
    else if (!emailok($email)) {
    	printf("-12"); // -12 == email address not valid
	    exit;
    }
    else if (strlen($user) < 2) {
    	printf("-13"); // -13 == username too short
	    exit;
    }
    else if (strlen($user) > 16) {
    	printf("-13"); // -13 == username too long
	    exit;
    }
    else if (strlen($vglpwd) < 6) {
    	printf("-14"); // -14 == password too short
	    exit;
    }
    else if (strlen($vglpwd) > 16) {
    	printf("-14"); // -14 == password too long
	    exit;
    }
    else if ($vglpwd != $pwd) {
    	printf("-15"); // -15 == invalid characters in password
	    exit;
    }
    else {
	    $uid = createUser($user, $email, md5($pwd));
	    $activation = getActivation($uid);

		sendEmailRegister($uid, $user, $activation, $ip);

	    printf("1#".$uid);
	    exit;
    }
 }

  //---------------------------------


 if ($cmd == "validate" && $val1 != "" && $val2 != "" && $val3 != "") {
     printf(login2($val1, $val2, $val3, true));
     exit;
  }


// if ($cmd == "login" && ($email != "" || $uid != "") && $pwd != "") {
//    if ($uid == "") {
//       $uid = getUID($email);
//    }
//    if (!isActive($uid)) {
//        printf("-4"); // -4 == account not activated!
//        exit;
//    }
//    if (login($uid, $pwd)) {
//    	printf("1#".$uid."#".getEmail($uid)."#".getUsername($uid)); // uid # email # username == login correct
////        printf("1"); // 1 == login correct
///    }
//    else if (login($uid, $pwd)) {
//    	printf("-11"); // -11 == new password not active
//    }
//    else  {
//    	printf("-1"); // -1 == login failed
//    }
//    exit;
// }

  //---------------------------------

 if ($cmd == "login2" && $val1 != "" && $val2 != "" && $val3 != "") {
     printf(login2($val1, $val2, $val3, false));
//     	printf("1#".$uid."#".getEmail($uid)."#".getUsername($uid)); // uid # email # username == login correct
     exit;
  }


  //---------------------------------


 if ($cmd == "resetpwd" && ($email != "" || $uid != "")) {
    if ($uid == "") {
       $email = base64_decode($email);
       $email = serverDec($email);
       $uid = getUID($email);
    } else {
       $uid = base64_decode($uid);
       $uid = serverDec($uid);
    }
    if (!isActive($uid)) {
        showMessage("Account not active yet. Follow the link in our email to activate the account."); // 1 == reset pwd success
        //printf("-4"); // -4 == account not activated!
        exit;
    }
    if (resetPWD($uid, $ip)) {
        showMessage("Password reset. Follow the link in our email to complete the reset."); // 1 == reset pwd success
    }
    else {
        // Fake the same message so users dont know if the email exists!
        showMessage("Password reset. Follow the link in our email to complete the reset."); // 1 == reset pwd success
        //showMessage("Password reset failed."); // 1 == reset pwd success
        //printf("-9"); // -9 == reset pwd failed!
    }
    exit;
 }

  //---------------------------------

 if ($cmd == "resendactivation" && ($email != "" || $uid != "")) {
    if ($uid == "") {
       $email = base64_decode($email);
       $email = serverDec($email);
       $uid = getUID($email);
    } else {
       $uid = base64_decode($uid);
       $uid = serverDec($uid);
    }
    if (isActive($uid)) {
    	// FAKE
        showMessage("Activation email sent. Follow the link in our email to complete the activation."); //
        //printf("-4"); // -4 == account alleady activated!
        exit;
    }
    $user = getUsername($uid);
	$activation = getActivation($uid);
	sendEmailRegister($uid, $user, $activation, $ip);
    showMessage("Activation email sent. Follow the link in our email to complete the activation."); //
    exit;
 }

   //---------------------------------

 // $val request is uid1#uid2#uid3... response is name1#name2#name3#-1#name5...
 if ($cmd == "getuser" && $session != "" && $val != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
        $uids = explode("#", $val);
        $printText = "";

	    foreach ($uids as $hostuid) {
	        $hostuid = decUid($uid, $hostuid);
	        //printf(getUsername($hostuid).", ".$uid." <BR>");
	        //printf(decText(7, "cyberpanda").", <BR>");
	        //printf(decText($uid,"cyberpanda").", <BR>");
	        //printf(decText($uid,getUsername($hostuid)).", <BR>");
	        if (strlen($printText) > 0) {
	           $printText = $printText."#";
	        }
	 	   if (isAllowedToGet($uid, $hostuid)) {
		        $printText = $printText.encText($uid, getUsername($hostuid));
	 	   }
	 	   else {
		        $printText = $printText."-1";
	 	   }
	    }
     	printf("1#".$printText);
     } else {
    	printf("-1"); // -1 == login failed or not activated
     }
     exit;
 }

  //---------------------------------

 if ($cmd == "updateuser" && $session != "" && $user != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
        $user = base64_decode($user);
	    $user = serverDec($user);

        $vgluser = $user;
        $user = formatuser($user);
    	if (strlen($user) < 2) {
    		printf("-13"); // -13 == username too short
		    exit;
		}
        else if (strlen($user) > 16) {
        	printf("-13"); // -13 == username too long
    	    exit;
        }
    	else if ($user != $vgluser) {
    		printf("-16"); // -16 == invalid characters in username
		    exit;
    	}
    	$query = "UPDATE users SET username = '".$user."' WHERE uid = '".$uid."'";
	    $result = mysql_query($query);
	    if ($result) {
	     	printf("1"); // 1 == updated
	    } else {
	    	printf("-5"); // -5 == update username failed
	    }
     } else {
    	printf("-1"); // -1 == login failed or not activated
     }
     exit;
 }

  //---------------------------------

// DO NOT ACTIVATE THIS FUNCTION IT EXPOSES ANY EMAIL ON THE SERVER
//
//
// if ($cmd == "getemail" && $uid != "" && $pwd != "") {
//     if (isActive($uid) && login($uid, $pwd)) {
//        $email = getEmail($uid);
//        if ($email > 0) {
//     		printf("1#".$email);
//        } else {
//	    	printf("-1"); // -1 == failed or not activated
//        }
//     } else {
//    	printf("-1"); // -1 == login failed or not activated
//     }
//     exit;
// }

  //---------------------------------

 if ($cmd == "updatepwd" && $session != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
        $val = base64_decode($val);
	    $val = serverDec($val);

        $vglpwd = formatuser($val);
    	if (strlen($vglpwd) < 6) {
    		printf("-14"); // -14 == password too short
	 	   exit;
    	}
        else if (strlen($vglpwd) > 16) {
        	printf("-14"); // -14 == password too long
    	    exit;
        }
    	else if ($vglpwd != $val) {
    		printf("-15"); // -15 == invalid characters in password
		    exit;
    	}
	    if (updatePwd($uid, $val, $ip)) {
	     	printf("1"); // 1 == updated
	    } else {
	    	printf("-6"); // -6 == update pwd failed
	    }
     } else {
    	printf("-1"); // -1 == login failed or not activated
     }
     exit;
 }

  //---------------------------------

 if ($cmd == "activateaccount" && $val != "") {
	if (activateAccount($val)) {
		showMessage("You account is now active!"); // 1 == activation done
	}
	else {
	 	showMessage("Invalid or outdated link."); // -3 == activation failed
	}
	exit;
 }

   //---------------------------------

 if ($cmd == "activatepwd" && $val != "") {
	if (activatePwd($val)) {
		showMessage("Your new password has now been activated!"); // 1 == activation done
	}
	else {
	 	showMessage("Invalid or outdated link."); // -7 == pwd activation failed
	}
	exit;
  }

  //---------------------------------

 if ($cmd == "send" && $session != "" && $val != "" && $host != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
        $values = explode("#", $val);
        if (count($values) >= 2) {
	        $created = $values[0];

	        $text = $values[1];
	        if (count($values) > 2) {
		        // ATTENTION: In the text there can be the "#" character, therefore reconstruct text with "#" here if count > 2!!!
		        // REPLACE WITH HASH-ESCAPE
	        	for ($i = 2; $i < count($values); $i++) {
	        		$text .= "@@@HASH@@@". $values[$i];
	        	}
	        }

	        $host = decUid($uid, $host);
	        if ($host == -1) {
	        	// unlikely but possible due to slight shift of clocks, there is a very small
	        	// interval of time where the checkbyte tells that the uid is invalid this means
	        	// that we must reject the message which should result in a smart client which
	        	// tries again!
	        	printf("-111"); // decrypted uid invalid == try again!
	        } else {
				printf(sendText($uid, $host, $text, $created));
	        }
        }
      }
      else {
 	     printf("-1");
      }
     exit;
 }

  //---------------------------------


 // val should have the largest mid received!
 if ($cmd == "receive" && $session != "" && $val != "") {
	 $uid = loginTmp($session);
     if ($uid != -1) {
			printf(receive($uid, $val));
     } else {
    		printf("-1"); // -1 == login failed or not activated
     }
     exit;
 }

  //---------------------------------

 // val should have the largest mid received! if this mid is larger than anything on the server, send "2" to recover the client! this means
 // that the message table on the server was meanwhile cleared
 if ($cmd == "have" && $session != "" && $val != "") {
  	 $uid = fastLogin($session);
     if ($uid != -1) {
		printf(have($uid, $val));
	} else {
    	printf("-1"); // 0 == login failed or not activated
	}
    exit;
 }

  //---------------------------------

 // val should be the key
 if ($cmd == "sendkey" && $session != "" && $val != "") {
  	 $uid = loginTmp($session);
     if ($uid != 1) {
		printf(sendkey($uid, $val));
     } else {
    	printf("-1"); // -1 == login failed or not activated
     }
     exit;
 }

  //---------------------------------

 if ($cmd == "clearkey" && $session != "") {
  	 $uid = loginTmp($session);
     if ($uid != 1) {
		printf(clearkey($uid));
     } else {
    	printf("-1"); // -1 == login failed or not activated
     }
     exit;
 }

  //---------------------------------

 // val should be the uid
 if ($cmd == "getkey" && $session != "" && $val != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
        $val = decUid($uid, $val);
        if (isAllowedToGet($uid, $val)) {
	 		printf(getkey($val));
	    } else {
     		printf("0"); // fake noe key
     	}
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------

 // val should be uid1#uid2#uid3... return will be 0#1#1  (0 no key, 1 key)
 if ($cmd == "haskey" && $session != "" && $val != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
 		printf(haskey($uid, $val));
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------
  //---------------------------------

 // The val are in form encUid1#encUid2#...
 if ($cmd == "backup" && $session != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
 		printf(backupUserlist($uid, $val, false));
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------

 if ($cmd == "restore" && $session != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
 		printf(restoreUserlist($uid, false));
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------

 // The val are in form encUid1#encUid2#...
 if ($cmd == "backupmanual" && $session != "" && $val != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
 		printf(backupUserlist($uid, $val, true));
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------

 if ($cmd == "restoremanual" && $session != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
 		printf(restoreUserlist($uid, true));
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------
  //---------------------------------

 if ($cmd == "updatephone" && $session != "" && $val != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
        $val = base64_decode($val);
	    $val = serverDec($val);
 		printf(updatePhone($uid, $val));
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------

 if ($cmd == "getphone" && $session != ""  && $val != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
        $val = decUid($uid, $val);
        $phone = getPhone($uid, $val);
        if ($phone == "") {
	 		printf("-1");
        }
        else {
	 		printf("1#".$phone);
        }
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------

 if ($cmd == "hasphone" && $session != "" && $val != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
 		printf(hasPhone($uid, $val));
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------
  //---------------------------------

 if ($cmd == "updateavatar" && $session != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
        //$val = decLongText($val);
        if (!$allowavatars) {
	     	printf("-44"); // -44 == avatars not allowed at this server
        }
        else if ($val != -1) {
	 		printf(updateAvatar($uid, $val));
        } else {
	     	printf("-22"); // -22 == avatar transmission error try again
        }
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------

 if ($cmd == "getavatar" && $session != ""  && $val != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
        $val = decUid($uid, $val);
        $avatar = getAvatar($uid, $val);
        if ($avatar == "") {
 	 		printf("-1");
        }
        else {
 	 		printf("1#".$avatar);
        }
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------

 if ($cmd == "hasavatar" && $session != "" && $val != "") {
 	  $uid = loginTmp($session);
      if ($uid != -1) {
 		printf(hasAvatar($uid, $val));
      } else {
     	printf("-1"); // -1 == login failed or not activated
      }
      exit;
 }

  //---------------------------------
  //---------------------------------

 // We only allow post here in order to test if the server is alive
 if ($postCmd == "pingpost") {
    printf($postVal);
    exit;
 }
 if ($cmd == "ping") {
    printf($val);
    exit;
 }


 if ($cmd == "serverkey") {
    printf("1#".getServerPubKey());
    exit;
 }

 if ($cmd == "mid") {
    printf("1#".getLargestMidServer());
    exit;
 }


 if ($cmd == "attachments") {
    if ($allowattachments) {
	    printf("1#".$maxattachmentkb);
    }
    else {
	    printf("0");
    }
    exit;
 }


  //---------------------------------
  //---------------------------------

  // THE FOLLOWING COMMANDS ARE JUST FOR DEBUGGING

 if ($cmd == "enc") {
    printf(encLongText(3, $val));
    exit;
 }
 if ($cmd == "dec") {
    printf(decLongText(3, $val));
    exit;
 }

// if ($cmd == "enc2") {
//  //  $encryptedText = serverEnc($val);
//  //  $e2 = urlencode ($encryptedText);
////    printf(str_replace("%", "%%", $e2));
//     printf(encUid($uid, $val));
//    exit;
// }

 //if ($cmd == "dec2") {
///	 $val = utf8_decode($val);
///     printf(serverDec($val));
 //    printf(decUid($uid, $val, true));
 //    exit;
 //}


// if ($cmd == "dec") {
//     printf(serverDec($val));
//     exit;
// }

// if ($cmd == "test") {
//    $encTextBase64 = encText($uid, $val);
// 	printf("ENC:'".$encTextBase64."'<BR><BR><BR><BR><BR><BR>");
//
//	printf("DEC:'".decText($uid, $encTextBase64)."'<BR><BR>");
//}

// if ($cmd == "test") {
//     printf("RND=".rand($rnduidincmin, $rnduidincmax));
//     exit;
// }

 if ($cmd == "php") {
     phpinfo();
     exit;
 }

// if ($cmd == "test") {
//	 header("Content-Type: text/plain");
// 	 printf("\n");
//	  printf("cmd: ".$cmd."\n");
//	  printf("host: ".$host."\n");
//	  printf("sessionlen: ".strlen($session)."\n");
//	  printf("session: ".$session."\n");
//	  printf("vallen: ".strlen($val)."\n");
//	  printf("val: ".$val."\n");
//	  exit;
// }

  //---------------------------------
  //---------------------------------

 //showMessage("This application requires the Delphino Cryptocator Android App.");

 // If the sever is in stealth mode and this was no valid request, then prentend
 // this is an invalid site.
 if ($serverstealthmode) {
	denyService();
 }

 printf("-");
 require('infoextended.php');
 exit;

 closedb($connection);




?>