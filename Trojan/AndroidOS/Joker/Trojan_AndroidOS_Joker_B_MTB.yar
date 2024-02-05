
rule Trojan_AndroidOS_Joker_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Joker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_00_0 = {67 64 2d 31 33 30 31 34 37 36 32 39 36 2e 63 6f 73 2e 6e 61 2d 74 6f 72 6f 6e 74 6f 2e 6d 79 71 63 6c 6f 75 64 2e 63 6f 6d } //01 00 
		$a_01_1 = {62 61 6f 62 75 74 6f 6e 67 } //01 00 
		$a_01_2 = {62 70 69 6c 6f 6e 67 } //01 00 
		$a_01_3 = {70 6f 72 6f 63 } //00 00 
		$a_00_4 = {5d 04 00 } //00 6c 
	condition:
		any of ($a_*)
 
}