
rule Trojan_AndroidOS_Spymax_N_MTB{
	meta:
		description = "Trojan:AndroidOS/Spymax.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 61 63 6b 61 67 65 2e 6e 61 6d 65 2e 73 75 66 66 69 78 } //01 00 
		$a_01_1 = {41 75 74 6f 5f 43 6c 69 63 6b } //01 00 
		$a_01_2 = {63 61 6e 47 6f 42 61 63 6b } //01 00 
		$a_01_3 = {77 69 66 69 5f 73 6c 65 65 70 5f 70 6f 6c 69 63 79 } //00 00 
	condition:
		any of ($a_*)
 
}