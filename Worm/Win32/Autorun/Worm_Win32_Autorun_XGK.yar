
rule Worm_Win32_Autorun_XGK{
	meta:
		description = "Worm:Win32/Autorun.XGK,SIGNATURE_TYPE_PEHSTR,07 00 06 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 75 73 72 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00 
		$a_01_1 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 75 73 72 5c 73 65 72 76 65 72 2e 65 78 65 } //01 00 
		$a_01_2 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 75 73 72 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00 
		$a_01_3 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00 
		$a_01_4 = {61 74 74 72 69 62 20 2b 48 20 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}