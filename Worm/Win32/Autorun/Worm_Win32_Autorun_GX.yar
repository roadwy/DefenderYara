
rule Worm_Win32_Autorun_GX{
	meta:
		description = "Worm:Win32/Autorun.GX,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 63 6e 2f 75 6c 2e 68 74 6d } //01 00 
		$a_01_1 = {52 65 63 79 63 6c 65 64 2e 65 78 65 } //01 00 
		$a_01_2 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 6f 70 65 6e 00 41 75 74 6f 52 75 6e } //01 00 
		$a_01_3 = {64 65 6c 65 74 65 00 2e 45 58 45 00 5c 4e 54 2d } //01 00 
		$a_01_4 = {5b 25 73 25 5d 00 5b 25 70 25 5d 00 5b 25 66 25 5d } //00 00 
	condition:
		any of ($a_*)
 
}