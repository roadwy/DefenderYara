
rule PWS_Win32_OnLineGames_ZFU{
	meta:
		description = "PWS:Win32/OnLineGames.ZFU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 1c 10 fe cb 88 1c 10 40 3b c1 7c f3 5f 5b c3 } //01 00 
		$a_01_1 = {64 3b 5d 6e 6a 63 62 70 2f 6b 71 68 } //00 00 
	condition:
		any of ($a_*)
 
}