
rule Trojan_AndroidOS_Maistealer_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Maistealer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 75 62 65 66 6c 69 63 5f 65 73 5f 63 6f 6d 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_1 = {63 6f 6d 2f 74 75 62 65 66 6c 69 63 5f 65 73 2f 63 6f 6d } //01 00 
		$a_01_2 = {68 61 73 53 65 6e 74 46 69 72 73 74 53 4d 53 } //01 00 
		$a_01_3 = {53 6d 73 52 65 63 65 69 76 65 72 48 65 6c 70 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Maistealer_A_MTB_2{
	meta:
		description = "Trojan:AndroidOS/Maistealer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6c 61 64 64 72 65 73 73 20 67 65 74 21 } //01 00 
		$a_00_1 = {73 74 72 4d 61 69 6c 4c 69 73 74 } //01 00 
		$a_00_2 = {61 64 64 72 65 73 73 63 61 70 2f 6c 69 73 74 2e 6c 6f 67 } //01 00 
		$a_00_3 = {63 6f 6e 73 75 6d 65 43 6f 6e 74 65 6e 74 } //01 00 
		$a_00_4 = {70 6f 73 74 4d 61 69 6c 4c 69 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}