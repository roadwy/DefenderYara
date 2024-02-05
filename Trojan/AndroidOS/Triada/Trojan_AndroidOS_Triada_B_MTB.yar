
rule Trojan_AndroidOS_Triada_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Triada.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6c 74 33 30 2f 74 65 73 74 2e 6a 73 70 } //01 00 
		$a_00_1 = {65 63 68 6f 20 72 67 5f 63 6d 64 5f 65 6e 64 5f 6d 61 67 69 63 } //01 00 
		$a_00_2 = {69 70 2e 63 6e 6b 79 68 67 2e 63 6f 6d 2f 69 70 2e 70 68 70 } //01 00 
		$a_00_3 = {58 5f 55 50 5f 43 4c 49 45 4e 54 5f 43 48 41 4e 4e 45 4c 5f 49 44 } //00 00 
	condition:
		any of ($a_*)
 
}