
rule Backdoor_BAT_AsyncRAT_L_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 41 6c 6c 63 45 78 } //01 00 
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d } //01 00 
		$a_01_2 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d } //01 00 
		$a_01_3 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 } //01 00 
		$a_01_4 = {44 65 6c 65 67 61 74 65 74 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 74 } //01 00 
		$a_01_5 = {44 65 6c 65 67 61 74 65 63 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 63 } //01 00 
		$a_01_6 = {52 73 6d 54 68 72 65 61 64 } //01 00 
		$a_01_7 = {45 78 65 63 75 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}