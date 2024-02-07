
rule PWS_Win32_Cinmag_B{
	meta:
		description = "PWS:Win32/Cinmag.B,SIGNATURE_TYPE_PEHSTR,49 00 49 00 0e 00 00 0a 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 59 61 68 6f 6f 21 20 49 44 20 74 68 61 74 20 6c 6f 67 67 65 64 20 70 61 73 73 20 53 65 6e 64 20 74 6f 20 69 74 } //0a 00  Your Yahoo! ID that logged pass Send to it
		$a_01_1 = {4a 75 73 74 20 74 79 70 65 20 49 44 20 64 6f 6e 27 74 20 75 73 65 20 20 40 79 61 68 6f 6f 2e 63 6f 6d } //01 00  Just type ID don't use  @yahoo.com
		$a_01_2 = {44 69 73 61 62 6c 65 20 4d 63 41 66 65 65 20 41 56 53 } //01 00  Disable McAfee AVS
		$a_01_3 = {44 69 73 61 62 6c 65 20 57 69 6e 20 46 69 72 65 57 61 6c 6c 20 78 70 32 } //01 00  Disable Win FireWall xp2
		$a_01_4 = {44 69 73 61 62 6c 65 20 4e 6f 72 74 6f 6e 20 41 56 53 } //01 00  Disable Norton AVS
		$a_01_5 = {44 69 73 61 62 6c 65 20 4d 73 43 6f 6e 66 69 67 } //01 00  Disable MsConfig
		$a_01_6 = {44 69 73 61 62 6c 65 20 52 65 67 65 64 69 74 } //01 00  Disable Regedit
		$a_01_7 = {44 69 73 61 62 6c 65 20 54 61 73 6b 6d 67 72 20 78 70 2d 32 6b } //01 00  Disable Taskmgr xp-2k
		$a_01_8 = {44 69 73 61 62 6c 65 20 59 21 20 53 61 76 65 20 50 61 73 73 } //0a 00  Disable Y! Save Pass
		$a_01_9 = {53 65 6e 64 20 57 69 6e 20 55 73 65 72 } //0a 00  Send Win User
		$a_01_10 = {41 75 74 6f 20 53 74 61 72 74 75 70 } //0a 00  Auto Startup
		$a_01_11 = {44 65 6c 65 74 65 20 4d 65 73 73 20 41 72 63 68 69 76 65 } //0a 00  Delete Mess Archive
		$a_01_12 = {53 65 6e 64 20 43 6f 6d 70 75 74 65 72 20 4e 61 6d 65 } //0a 00  Send Computer Name
		$a_01_13 = {53 65 6e 64 20 59 61 68 6f 6f 20 50 61 73 73 77 6f 72 64 } //00 00  Send Yahoo Password
	condition:
		any of ($a_*)
 
}