
rule Trojan_AndroidOS_Joker_C{
	meta:
		description = "Trojan:AndroidOS/Joker.C,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 62 5f 76 65 72 73 69 6f 6e 5f 69 64 } //01 00 
		$a_00_1 = {48 6b 4f 6e 54 6f 75 63 68 4c 69 74 65 6e 65 72 } //01 00 
		$a_00_2 = {4c 63 6e 2f 6d 68 6f 6b 2f 73 64 6a 6b 2f 46 61 63 65 62 6f 6f 6b 55 74 69 6c 73 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}