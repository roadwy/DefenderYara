
rule Worm_Win32_Autorun_GV{
	meta:
		description = "Worm:Win32/Autorun.GV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f8 03 74 05 83 f8 02 75 69 68 a0 00 00 00 68 90 01 04 ff d5 90 00 } //01 00 
		$a_01_1 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00 
		$a_01_2 = {5b 41 75 74 6f 52 75 6e 5d } //01 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 63 25 63 25 63 2e 25 63 25 63 25 63 25 63 25 63 25 63 2e 25 63 25 63 25 63 2f 25 63 2e 25 63 25 63 25 63 } //00 00 
	condition:
		any of ($a_*)
 
}