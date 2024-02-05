
rule Trojan_AndroidOS_Wroba_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Wroba.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 41 64 64 53 4d 53 2e 61 73 70 78 } //01 00 
		$a_01_1 = {41 64 64 42 61 6e 6b 50 77 64 54 61 73 6b } //01 00 
		$a_01_2 = {43 68 65 63 6b 53 6d 73 4d 65 73 73 61 67 65 73 } //01 00 
		$a_01_3 = {2f 74 65 6c 77 65 62 73 65 72 76 69 63 65 73 74 77 6f 2e 61 73 6d 78 } //01 00 
		$a_01_4 = {52 6f 6f 74 53 4d 53 } //01 00 
		$a_01_5 = {41 64 64 62 61 6e 6b 6d 65 73 73 61 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}