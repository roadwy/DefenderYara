
rule PWS_Win32_Perfwo_E{
	meta:
		description = "PWS:Win32/Perfwo.E,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 63 63 65 70 74 3a 20 2a 2f 2a 00 48 54 54 50 2f 31 2e 30 } //01 00 
		$a_01_1 = {2e 64 6c 6c 00 48 6f 6f 6b 6f 66 66 00 48 6f 6f 6b 6f 6e } //01 00 
		$a_01_2 = {65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 } //01 00 
		$a_01_3 = {44 6f 50 61 63 74 68 2e 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_4 = {47 61 6d 65 50 61 74 63 68 } //00 00 
	condition:
		any of ($a_*)
 
}