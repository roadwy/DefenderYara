
rule Worm_Win32_Autorun_AAI{
	meta:
		description = "Worm:Win32/Autorun.AAI,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 44 6f 53 2c 20 74 79 70 65 20 73 74 6f 70 66 6c 6f 6f 64 20 74 6f 20 73 74 6f 70 } //01 00 
		$a_01_1 = {25 73 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00 
		$a_01_2 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 6d 6f 64 65 3d 64 69 73 61 62 6c 65 20 70 72 6f 66 69 6c 65 3d 61 6c 6c } //01 00 
		$a_01_3 = {49 43 57 6f 72 6d 5c 52 65 6c 65 61 73 65 5c 49 43 57 6f 72 6d 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}