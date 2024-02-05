
rule Worm_Win32_Rethed_A{
	meta:
		description = "Worm:Win32/Rethed.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 69 72 73 74 3d 31 26 64 61 74 61 3d 25 73 2a 25 73 20 25 73 2a 25 73 2a 25 73 2a 25 73 } //01 00 
		$a_01_1 = {5c 45 74 68 65 72 5c 42 69 6e 5c 45 74 68 65 72 2e 70 64 62 } //01 00 
		$a_01_2 = {54 00 5a 00 61 00 70 00 43 00 6f 00 6d 00 6d 00 75 00 6e 00 69 00 63 00 61 00 74 00 6f 00 72 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}