
rule Trojan_AndroidOS_Boogr_T{
	meta:
		description = "Trojan:AndroidOS/Boogr.T,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 69 73 74 70 69 63 6e 69 63 } //01 00 
		$a_01_1 = {69 73 50 72 69 63 65 53 74 61 72 74 73 57 69 74 68 43 75 72 72 65 6e 63 79 } //01 00 
		$a_01_2 = {4c 63 6f 6d 2f 63 65 6d 65 6e 74 2f 62 75 6c 6c 65 74 2f 74 69 67 65 72 } //01 00 
		$a_01_3 = {73 74 72 75 67 67 6c 65 6e 6f 74 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}