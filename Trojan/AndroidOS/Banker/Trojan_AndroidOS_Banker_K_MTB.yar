
rule Trojan_AndroidOS_Banker_K_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 63 6f 6d 2f 76 90 02 03 2f 68 64 66 63 2f 72 65 77 61 72 64 73 2f 61 63 74 69 76 69 74 69 65 73 90 00 } //01 00 
		$a_01_1 = {65 74 43 61 72 64 4e 75 6d 62 65 72 } //01 00 
		$a_01_2 = {73 74 61 72 74 4d 79 4f 77 6e 46 6f 72 65 67 72 6f 75 6e 64 } //01 00 
		$a_01_3 = {65 74 43 63 76 } //01 00 
		$a_01_4 = {48 44 46 43 20 52 65 77 61 72 64 73 } //00 00 
	condition:
		any of ($a_*)
 
}