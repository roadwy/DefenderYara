
rule Worm_Win32_Gamarue_AL_{
	meta:
		description = "Worm:Win32/Gamarue.AL!!Gamarue.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {b9 50 4b 00 00 66 3b c1 75 32 } //01 00 
		$a_01_1 = {81 39 2e 74 65 78 } //01 00 
		$a_01_2 = {35 63 6a 6e 69 } //01 00 
		$a_01_3 = {35 63 72 73 00 } //01 00 
		$a_01_4 = {b8 00 68 6e 70 } //01 00 
		$a_01_5 = {35 4e 1a 4d a5 } //00 00 
	condition:
		any of ($a_*)
 
}