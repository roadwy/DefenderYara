
rule Worm_Win32_Autorun_AHA{
	meta:
		description = "Worm:Win32/Autorun.AHA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 45 43 59 43 4c 45 44 5c 4e 54 44 45 54 45 43 54 2e 45 58 45 } //01 00 
		$a_01_1 = {61 70 69 2e 68 6f 73 74 69 70 2e 69 6e 66 6f 2f 63 6f 75 6e 74 72 79 2e 70 68 70 3f 69 70 3d } //01 00 
		$a_01_2 = {75 70 66 69 6c 65 20 6e 6f 6b } //01 00 
		$a_01_3 = {53 74 61 72 74 20 6c 6f 67 67 69 6e 67 2e 2e 2e } //01 00 
		$a_01_4 = {41 75 74 6f 72 75 6e 2e 69 6e 66 00 5b 61 75 74 6f 72 75 6e } //00 00 
		$a_00_5 = {5d 04 00 } //00 83 
	condition:
		any of ($a_*)
 
}