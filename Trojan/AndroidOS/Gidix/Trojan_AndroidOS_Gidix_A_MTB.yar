
rule Trojan_AndroidOS_Gidix_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Gidix.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6d 73 41 63 74 69 6f 6e 5f 53 65 6e 64 } //01 00 
		$a_01_1 = {73 65 74 4d 73 67 53 6c 69 65 6e 74 } //01 00 
		$a_01_2 = {47 65 74 50 68 6f 6e 65 49 6e 66 6f } //01 00 
		$a_01_3 = {72 65 63 70 68 6f 6e 65 69 64 } //01 00 
		$a_01_4 = {50 68 6f 6e 65 53 74 61 74 75 73 43 68 65 63 6b } //01 00 
		$a_01_5 = {73 6c 69 65 6e 74 43 68 65 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}