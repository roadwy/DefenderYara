
rule PWS_Win32_OnLineGames_CRS_sys{
	meta:
		description = "PWS:Win32/OnLineGames.CRS!sys,SIGNATURE_TYPE_PEHSTR,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //02 00 
		$a_01_1 = {47 61 6d 65 48 61 63 6b 5c 48 6f 6f 6b 44 6c 6c 44 72 69 76 65 72 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c 68 6f 6f 6b 64 6c 6c 2e 70 64 62 } //02 00 
		$a_01_2 = {00 67 6e 61 69 78 6e 61 75 68 71 71 00 } //02 00 
		$a_01_3 = {00 6e 61 69 78 75 68 7a 00 } //01 00 
		$a_01_4 = {00 6e 69 6c 75 77 00 } //02 00 
		$a_01_5 = {8b c0 8b c0 8b c0 8b c0 90 90 90 90 } //00 00 
	condition:
		any of ($a_*)
 
}