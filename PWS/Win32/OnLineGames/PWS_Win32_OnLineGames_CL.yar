
rule PWS_Win32_OnLineGames_CL{
	meta:
		description = "PWS:Win32/OnLineGames.CL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 69 72 31 2e 64 61 74 } //01 00 
		$a_00_1 = {2e 64 6c 6c 00 68 6f 6f 6b 6f 66 66 00 68 6f 6f 6b 6f 6e } //01 00 
		$a_03_2 = {7e 24 53 56 8b 74 24 18 8b dd 2b de 8a 04 33 55 04 90 01 01 34 90 01 01 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}