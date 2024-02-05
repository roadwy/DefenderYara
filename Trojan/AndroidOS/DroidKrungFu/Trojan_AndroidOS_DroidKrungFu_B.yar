
rule Trojan_AndroidOS_DroidKrungFu_B{
	meta:
		description = "Trojan:AndroidOS/DroidKrungFu.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 63 68 6d 6f 64 20 37 35 35 20 2f 73 79 73 74 65 6d 2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //01 00 
		$a_01_1 = {2f 57 65 62 56 69 65 77 2e 64 62 } //01 00 
		$a_01_2 = {2f 73 79 73 74 65 6d 2f 65 74 63 2f 2e 72 69 6c 64 5f 63 66 67 } //01 00 
		$a_01_3 = {2f 73 65 63 62 69 6e 6f } //00 00 
	condition:
		any of ($a_*)
 
}