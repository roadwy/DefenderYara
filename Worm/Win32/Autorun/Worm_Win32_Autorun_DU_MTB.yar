
rule Worm_Win32_Autorun_DU_MTB{
	meta:
		description = "Worm:Win32/Autorun.DU!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 47 00 61 00 61 00 72 00 61 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_1 = {57 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 } //01 00 
		$a_01_2 = {47 65 74 44 72 69 76 65 54 79 70 65 41 } //01 00 
		$a_01_3 = {4b 69 6c 6c 41 56 } //00 00 
	condition:
		any of ($a_*)
 
}