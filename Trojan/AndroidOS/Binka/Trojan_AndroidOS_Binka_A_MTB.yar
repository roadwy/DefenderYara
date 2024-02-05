
rule Trojan_AndroidOS_Binka_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Binka.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 73 53 74 61 72 74 43 41 4c 4c } //01 00 
		$a_01_1 = {73 65 6e 74 5f 43 61 6c 6c 5f 44 65 74 61 69 6c 73 } //01 00 
		$a_01_2 = {69 73 53 74 61 72 74 53 4d 53 } //01 00 
		$a_01_3 = {63 68 65 6b 41 64 6d 69 6e 41 63 63 65 73 73 } //01 00 
		$a_01_4 = {73 65 6e 74 5f 73 6d 73 6c 69 73 74 5f 74 6f 5f 73 65 72 76 65 72 } //01 00 
		$a_01_5 = {69 73 43 6f 6e 74 61 63 74 4c 69 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}