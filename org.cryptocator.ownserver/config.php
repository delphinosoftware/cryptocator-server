<?
//================================================================================================
//===        D E L P H I N O     C R Y P T O C A T O R     C O N F I G U R A T I O N           ===
//================================================================================================


$BASEURL = "http://www.cryptocator.org/";
$WEBMASTER = "webaster@cryptocator.org";
$DBUSER = "dummy";
$DBPWD = "Sando441";
$DBURL = "localhost";
$DBNAME = "cryptocator";
$CONST_EMAILHEADER  = "From: Delphino Cryptocator <noreply@cryptocator.org>\n";
$CONST_EMAILHEADER .= "Content-Type: text/plain; charset=us-ascii\n";
$CONST_EMAILHEADER .= "Content-transfer-encoding: quoted-printable";
$CONST_EMAILHEADER .= "MIME-Version: 1.0\n";

$allownewaccounts = true; // disallow any new accounts
$serverstealthmode = false; // if an invalid url is entered, a 500 internal server error is presented instead

$allowattachments = true;  // attachments for internet messages allowed
$maxattachmentkb = 30;     // maximum KB size of attachments allowed for internet messages

$rnduidincmin = 1;     // mininum random increment for UID to add if a new user ID is created must at least be 1!
$rnduidincmax = 100;   // maximum random increment for UID to add if a new user ID is created must at least be 1!

$bantimemin = 10;  // ban for 10 minutes, set to 0 for disabling this security feature!
$bantimeinc = 100; // increase 100% == double the bantime after each attack
$bantimeout = 24;  // hours

$dostimemin = 2;     // inspect the last 2 minutes
$dosmaxnumreq = 100; // allow 10 requests in the last 2 minutes from the same IP

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