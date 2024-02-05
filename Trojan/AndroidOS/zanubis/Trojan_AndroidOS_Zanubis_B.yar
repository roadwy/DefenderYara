
rule Trojan_AndroidOS_Zanubis_B{
	meta:
		description = "Trojan:AndroidOS/Zanubis.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 61 74 6f 73 5f 69 6e 69 63 69 61 6c 65 73 5f 63 6c 69 65 6e 74 65 } //01 00 
		$a_01_1 = {72 65 76 5f 70 65 72 6d 69 73 6f 5f 73 6d 73 } //01 00 
		$a_01_2 = {74 61 67 65 74 73 5f 66 69 6e 64 } //01 00 
		$a_01_3 = {73 6f 63 6b 5f 65 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}