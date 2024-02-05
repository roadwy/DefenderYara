
rule Trojan_AndroidOS_DroidKrungFu_A{
	meta:
		description = "Trojan:AndroidOS/DroidKrungFu.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 0b 63 70 4c 65 67 61 63 79 52 65 73 00 } //01 00 
		$a_01_1 = {2e 63 6f 6d 3a 38 35 31 31 2f 73 65 61 72 63 68 2f 73 61 79 68 69 2e 70 68 70 00 } //01 00 
		$a_01_2 = {2f 72 61 74 63 00 } //00 00 
	condition:
		any of ($a_*)
 
}