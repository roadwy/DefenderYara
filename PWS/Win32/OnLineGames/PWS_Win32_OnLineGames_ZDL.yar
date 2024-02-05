
rule PWS_Win32_OnLineGames_ZDL{
	meta:
		description = "PWS:Win32/OnLineGames.ZDL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {67 6f 74 6f 20 74 72 79 20 90 02 10 69 66 20 65 78 69 73 74 20 25 73 90 02 10 64 65 6c 20 25 73 90 02 10 3a 74 72 79 90 02 10 2e 62 61 74 90 02 ff 48 4d 5f 4d 45 53 53 90 02 10 4c 4c 90 02 50 2e 73 79 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}