
rule PWS_Win32_OnLineGames_FC{
	meta:
		description = "PWS:Win32/OnLineGames.FC,SIGNATURE_TYPE_PEHSTR,2a 00 2a 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //0a 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {71 71 6c 6f 67 69 6e 2e 65 78 65 } //0a 00  qqlogin.exe
		$a_01_2 = {61 63 74 69 6f 6e 3d 6f 6b 26 75 3d } //0a 00  action=ok&u=
		$a_01_3 = {54 65 6e 51 51 41 63 63 6f 75 6e 74 } //01 00  TenQQAccount
		$a_01_4 = {2f 6d 69 62 61 6f 2e 61 73 70 } //01 00  /mibao.asp
		$a_01_5 = {2f 67 61 69 62 61 6f 2e 61 73 70 } //01 00  /gaibao.asp
		$a_01_6 = {2f 66 6c 61 73 68 2e 61 73 70 } //01 00  /flash.asp
		$a_01_7 = {2f 6d 61 69 6c 2e 61 73 70 } //00 00  /mail.asp
	condition:
		any of ($a_*)
 
}