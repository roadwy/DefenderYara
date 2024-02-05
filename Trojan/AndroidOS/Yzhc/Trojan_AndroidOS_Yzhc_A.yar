
rule Trojan_AndroidOS_Yzhc_A{
	meta:
		description = "Trojan:AndroidOS/Yzhc.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 75 73 69 6e 65 73 73 6e 61 6d 62 65 72 } //01 00 
		$a_01_1 = {74 72 79 20 6e 65 77 20 6f 6e 65 20 64 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_01_2 = {73 70 5f 62 6c 6f 63 6b 65 64 5f 63 6f 6e 74 65 6e 74 3a } //01 00 
		$a_01_3 = {26 62 6c 61 63 6b 3d } //01 00 
		$a_03_4 = {26 73 70 6e 90 03 01 01 75 61 6d 62 65 72 3d 90 00 } //01 00 
		$a_01_5 = {2b 38 36 31 33 38 30 30 37 35 35 35 30 30 } //01 00 
		$a_01_6 = {70 75 73 68 5f 73 68 6f 77 5f 63 6c 69 65 6e 74 3a } //00 00 
	condition:
		any of ($a_*)
 
}