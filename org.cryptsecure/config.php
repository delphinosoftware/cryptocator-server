<?
//================================================================================================
//===        D E L P H I N O     C R Y P T S E C U R E     C O N F I G U R A T I O N           ===
//================================================================================================


$BASEURL = "http://www.cryptsecure.org/";
$WEBMASTER = "webaster@cryptsecure.org";
$DBUSER = "dummy";
$DBPWD = "Sando441";
$DBURL = "localhost";
$DBNAME = "cryptsecure";
$CONST_EMAILHEADER  = "From: Delphino CryptSecure <noreply@cryptsecure.org>\n";
$CONST_EMAILHEADER .= "Content-Type: text/plain; charset=us-ascii\n";
$CONST_EMAILHEADER .= "Content-transfer-encoding: quoted-printable";
$CONST_EMAILHEADER .= "MIME-Version: 1.0\n";

$allownewaccounts = true; // disallow any new accounts
$allowavatars = true;
$serverstealthmode = false; // if an invalid url is entered, a 500 internal server error is presented instead

$allowgroups = false;
$timeoutforinvitations = 24; // within 24 hours a group invitation must be accepted

$allowattachments = true;  // attachments for internet messages allowed
$maxattachmentkb = 30;     // maximum KB size of attachments allowed for internet messages

$rnduidincmin = 1;     // mininum random increment for UID to add if a new user ID is created must at least be 1!
$rnduidincmax = 100;   // maximum random increment for UID to add if a new user ID is created must at least be 1!

$bantimemin = 10;  // ban for 10 minutes, set to 0 for disabling this security feature!
$bantimeinc = 100; // increase 100% == double the bantime after each attack
$bantimeout = 24;  // hours

$dostimemin = 2;      // inspect the last 2 minutes
$dosmaxnumreq = 1000; // allow 10 requests in the last 2 minutes from the same IP

$welcomemessage = "Welcome to Delphino CryptSecure!@@@NEWLINE@@@@@@NEWLINE@@@Your account has just been activated. You can now exchange securely encrypted messages with other people who also value uncompromised privacy.@@@NEWLINE@@@@@@NEWLINE@@@Give your UID \'".$uid."\' to anyone who should be able to add you. Ask friends about their UIDs in order to add them. To add UIDs, go to the main window and select \'Add User\' from the context menu.@@@NEWLINE@@@@@@NEWLINE@@@Find more information here: http://www.cryptsecure.org@@@NEWLINE@@@@@@NEWLINE@@@Tell a good friend about CryptSecure if you like it!";


$ipaddress = $_SERVER['REMOTE_ADDR'];
//printf($ipaddress);

//================================================================================================
//================================================================================================

function getAttackName($attackid) {
	if ($attackid == 1) {
		return "SALT REUSED";
	}
	if ($attackid == 2) {
		return "LOGIN REUSED";
	}
	if ($attackid == 3) {
		return "WRONG PWD";
	}
	if ($attackid == 4) {
		return "DOS";
	}
}


?>