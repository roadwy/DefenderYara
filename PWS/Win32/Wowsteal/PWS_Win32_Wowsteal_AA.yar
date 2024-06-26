
rule PWS_Win32_Wowsteal_AA{
	meta:
		description = "PWS:Win32/Wowsteal.AA,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe1 00 ffffffdf 00 1c 00 00 64 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //64 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  \Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {5c 41 70 70 45 76 65 6e 74 73 5c 53 63 68 65 6d 65 73 5c 41 70 70 73 5c 45 78 70 6c 6f 72 65 72 5c 4e 61 76 69 67 61 74 69 6e 67 5c 2e 63 75 72 72 65 6e 74 } //01 00  \AppEvents\Schemes\Apps\Explorer\Navigating\.current
		$a_01_3 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //01 00  Content-Type: application/x-www-form-urlencoded
		$a_01_4 = {55 74 69 6c 4d 69 6e 64 20 48 54 54 50 47 65 74 } //01 00  UtilMind HTTPGet
		$a_01_5 = {5c 4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 54 65 6d 70 5c 75 70 64 61 74 65 2e 65 78 65 } //01 00  \Local Settings\Temp\update.exe
		$a_01_6 = {42 6c 61 63 6b 53 75 6e 44 6f 6d 61 69 6e 73 } //01 00  BlackSunDomains
		$a_01_7 = {42 6c 61 63 6b 53 75 6e 4e 65 78 74 53 65 72 76 65 72 } //01 00  BlackSunNextServer
		$a_01_8 = {42 6c 61 63 6b 53 75 6e 4e 65 78 74 53 65 72 76 65 72 54 69 6d 65 72 } //01 00  BlackSunNextServerTimer
		$a_01_9 = {42 6c 61 63 6b 53 75 6e 47 61 74 65 77 61 79 44 6f 6e 65 53 74 72 69 6e 67 } //01 00  BlackSunGatewayDoneString
		$a_01_10 = {2f 76 6f 69 64 2e 70 68 70 } //01 00  /void.php
		$a_00_11 = {28 43 52 41 43 4b 29 20 } //01 00  (CRACK) 
		$a_00_12 = {28 4b 45 59 20 47 45 4e 29 20 } //01 00  (KEY GEN) 
		$a_00_13 = {28 50 41 54 43 48 29 20 } //01 00  (PATCH) 
		$a_00_14 = {28 46 55 4c 4c 29 20 } //01 00  (FULL) 
		$a_01_15 = {3c 53 68 61 72 65 3e } //01 00  <Share>
		$a_01_16 = {5b 21 21 5e 2a 2a 5d } //01 00  [!!^**]
		$a_01_17 = {43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 } //01 00  Common Files
		$a_01_18 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 } //01 00  Application Data
		$a_01_19 = {46 61 76 6f 72 69 74 65 73 } //01 00  Favorites
		$a_01_20 = {4d 79 20 44 6f 63 75 6d 65 6e 74 73 } //01 00  My Documents
		$a_01_21 = {4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 } //01 00  Local Settings
		$a_01_22 = {44 65 66 61 75 6c 74 20 55 73 65 72 } //01 00  Default User
		$a_01_23 = {41 6c 6c 20 55 73 65 72 73 } //01 00  All Users
		$a_01_24 = {44 43 50 6c 75 73 50 6c 75 73 2e 78 6d 6c } //01 00  DCPlusPlus.xml
		$a_01_25 = {74 00 72 00 61 00 79 00 6e 00 6f 00 74 00 69 00 66 00 79 00 } //01 00  traynotify
		$a_01_26 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 } //01 00  http://www.google.com/
		$a_01_27 = {48 00 4f 00 4d 00 45 00 50 00 41 00 54 00 48 00 } //00 00  HOMEPATH
	condition:
		any of ($a_*)
 
}