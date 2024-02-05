
rule Trojan_AndroidOS_SAgnt_L_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 79 73 5f 73 65 6e 64 5f 63 6f 6e 74 65 6e 74 73 } //01 00 
		$a_01_1 = {61 70 70 2e 6c 61 73 74 43 61 6c 6c 65 64 4e 75 6d 62 65 72 } //01 00 
		$a_01_2 = {4e 6f 74 69 66 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_3 = {53 65 74 54 6e 6b 54 72 61 63 6b 65 72 } //01 00 
		$a_01_4 = {73 65 6e 64 49 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}