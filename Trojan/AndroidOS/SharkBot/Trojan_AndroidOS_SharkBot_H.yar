
rule Trojan_AndroidOS_SharkBot_H{
	meta:
		description = "Trojan:AndroidOS/SharkBot.H,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 20 77 68 61 74 20 63 69 74 79 20 6f 72 20 74 6f 77 6e 20 64 69 64 20 79 6f 75 72 20 6d 6f 74 68 65 72 20 61 6e 64 20 66 61 74 68 65 72 20 6d 65 65 74 } //01 00 
		$a_01_1 = {70 61 63 6b 61 67 65 20 72 65 63 65 72 76 65 72 20 64 61 74 61 } //01 00 
		$a_01_2 = {73 63 61 6e 20 69 73 6e 74 61 6c 6c 20 61 70 6b } //01 00 
		$a_01_3 = {71 75 65 73 74 69 6f 6e 20 61 6e 73 65 72 } //01 00 
		$a_01_4 = {72 6f 6f 74 20 3d } //00 00 
	condition:
		any of ($a_*)
 
}