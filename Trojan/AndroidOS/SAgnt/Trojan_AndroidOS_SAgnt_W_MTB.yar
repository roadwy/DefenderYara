
rule Trojan_AndroidOS_SAgnt_W_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.W!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 6f 75 61 5f 72 65 64 2e 70 68 70 3f } //01 00 
		$a_01_1 = {48 75 72 72 61 79 57 69 72 65 6c 65 73 73 4f 41 } //01 00 
		$a_01_2 = {63 6f 6d 2f 73 6e 64 61 2f 79 6f 75 6e 69 2f 59 6f 75 4e 69 } //01 00 
		$a_01_3 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 69 6e 62 6f 78 } //01 00 
		$a_01_4 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}