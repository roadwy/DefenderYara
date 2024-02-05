
rule Trojan_AndroidOS_DroidKrungFu_I{
	meta:
		description = "Trojan:AndroidOS/DroidKrungFu.I,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 55 70 64 61 74 65 43 68 65 63 6b 24 31 3b } //01 00 
		$a_01_1 = {55 70 64 61 74 65 43 68 65 63 6b 2e 6a 61 76 61 } //01 00 
		$a_03_2 = {61 63 63 65 73 73 24 30 90 01 02 61 63 63 65 73 73 24 31 90 00 } //01 00 
		$a_03_3 = {6c 6f 61 64 4c 69 62 72 61 72 79 90 01 02 6d 43 68 90 01 02 6d 49 64 90 00 } //01 00 
		$a_03_4 = {6d 65 74 61 44 61 74 61 90 01 02 4d 59 41 44 5f 50 49 44 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}