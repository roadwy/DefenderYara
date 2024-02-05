
rule Trojan_AndroidOS_lemon_A_MTB{
	meta:
		description = "Trojan:AndroidOS/lemon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 74 49 4d 45 49 41 6e 64 56 65 72 73 69 6f 6e } //01 00 
		$a_01_1 = {6d 64 35 5f 6e 65 74 77 6f 72 6b } //01 00 
		$a_01_2 = {4d 45 53 53 41 47 45 5f 49 4e 54 4f 5f 4f 4e 4c 49 4e 45 5f 42 4f 4f 4b 53 } //01 00 
		$a_01_3 = {61 75 74 6f 55 70 64 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}