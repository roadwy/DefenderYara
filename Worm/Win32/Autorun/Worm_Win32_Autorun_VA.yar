
rule Worm_Win32_Autorun_VA{
	meta:
		description = "Worm:Win32/Autorun.VA,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 6e 00 75 00 72 00 6f 00 74 00 75 00 61 00 5c 00 3a 00 } //01 00 
		$a_01_1 = {5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 } //01 00 
		$a_01_2 = {5f 5f 76 62 61 46 69 6c 65 4f 70 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}