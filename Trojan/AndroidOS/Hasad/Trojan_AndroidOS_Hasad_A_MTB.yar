
rule Trojan_AndroidOS_Hasad_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Hasad.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 70 69 2e 63 6c 69 70 68 6f 74 2e 6d 65 } //01 00 
		$a_01_1 = {54 72 61 63 6b 69 6e 67 53 65 72 76 69 63 65 } //01 00 
		$a_01_2 = {63 6f 6d 2f 68 64 63 2f 73 64 6b 2f 61 75 74 6f 73 75 62 } //01 00 
		$a_01_3 = {68 64 63 73 75 62 } //00 00 
	condition:
		any of ($a_*)
 
}