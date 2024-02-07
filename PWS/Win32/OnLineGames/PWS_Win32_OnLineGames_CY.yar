
rule PWS_Win32_OnLineGames_CY{
	meta:
		description = "PWS:Win32/OnLineGames.CY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 63 74 69 6f 6e 3d 66 72 65 73 68 26 7a 74 3d 73 75 63 63 6d 62 68 26 75 3d } //01 00  action=fresh&zt=succmbh&u=
		$a_01_1 = {49 6e 74 65 72 6e 65 74 51 75 65 72 79 44 61 74 61 41 76 61 69 6c 61 62 6c 65 } //01 00  InternetQueryDataAvailable
		$a_00_2 = {73 74 61 72 74 5c 55 73 65 72 53 65 74 74 69 6e 67 2e 69 6e 69 } //01 00  start\UserSetting.ini
		$a_00_3 = {71 71 6c 6f 67 69 6e 2e 65 78 65 } //01 00  qqlogin.exe
		$a_00_4 = {61 63 74 69 6f 6e 3d 6f 6b 26 75 3d } //00 00  action=ok&u=
	condition:
		any of ($a_*)
 
}