
rule Worm_Win32_Perkesh_gen_B{
	meta:
		description = "Worm:Win32/Perkesh.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {7e 0d 8a 0c 18 f6 d1 88 0c 18 40 3b c6 7c f3 } //02 00 
		$a_01_1 = {3c 05 75 1e 33 c9 8a cc 84 c9 75 07 68 24 65 40 00 eb 05 68 18 65 40 00 ff 15 } //01 00 
		$a_01_2 = {75 72 6c 6d 30 6e 2e 64 6c 6c } //01 00 
		$a_01_3 = {5c 64 72 69 76 65 72 73 5c 42 65 65 70 2e 73 79 73 } //00 00 
	condition:
		any of ($a_*)
 
}