
rule Trojan_AndroidOS_Arspam_A{
	meta:
		description = "Trojan:AndroidOS/Arspam.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 49 43 49 72 65 70 6f 72 74 41 52 2e 70 64 66 } //01 00 
		$a_01_1 = {61 6c 41 72 61 62 69 79 79 61 68 2e 6a 61 76 61 } //01 00 
		$a_01_2 = {73 69 6c 65 72 69 61 2f 61 6c 73 61 6c 61 68 } //01 00 
		$a_01_3 = {41 74 74 61 63 68 69 6e 67 20 47 50 53 20 6c 69 73 74 65 6e 65 72 2e 2e 2e } //01 00 
		$a_01_4 = {61 6c 73 61 6c 61 68 2e 73 69 6c 65 72 69 61 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}