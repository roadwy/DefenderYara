
rule PWS_Win32_OnLineGames_MB{
	meta:
		description = "PWS:Win32/OnLineGames.MB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 75 70 4e 6f 74 69 66 79 2e 65 78 65 } //01 00  SoftupNotify.exe
		$a_01_1 = {47 61 6d 65 20 4f 76 65 72 00 00 00 48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 6e } //01 00 
		$a_01_2 = {43 3a 5c 46 57 2e 46 57 } //00 00  C:\FW.FW
	condition:
		any of ($a_*)
 
}