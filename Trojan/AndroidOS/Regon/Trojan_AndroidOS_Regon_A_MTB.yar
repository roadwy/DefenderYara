
rule Trojan_AndroidOS_Regon_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Regon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 70 53 65 72 76 65 72 41 70 70 73 4c 69 73 74 } //01 00 
		$a_01_1 = {75 70 53 65 72 76 65 72 43 6f 6e 74 61 63 74 4c 69 73 74 } //01 00 
		$a_01_2 = {75 70 53 65 72 76 65 72 43 61 6c 6c 4c 6f 67 73 } //01 00 
		$a_01_3 = {69 73 73 68 6f 77 63 61 72 64 } //01 00 
		$a_01_4 = {68 6f 6f 6b 63 61 6c 6c 73 } //01 00 
		$a_01_5 = {67 65 74 5f 62 72 6f 77 68 69 73 74 } //01 00 
		$a_01_6 = {73 65 74 5f 69 6e 6a 65 63 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}