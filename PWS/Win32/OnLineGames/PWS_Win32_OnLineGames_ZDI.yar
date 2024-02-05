
rule PWS_Win32_OnLineGames_ZDI{
	meta:
		description = "PWS:Win32/OnLineGames.ZDI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {77 77 2e 63 c7 45 90 01 01 6b 38 38 38 c7 45 90 01 01 36 36 2e 63 c7 45 90 01 01 6f 6d 2f 63 c7 45 90 01 01 79 38 37 36 c7 45 90 01 01 2f 6c 69 6e c7 45 90 01 01 31 31 31 2e c7 45 90 01 01 61 73 70 00 e8 90 01 02 00 00 90 00 } //01 00 
		$a_00_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}