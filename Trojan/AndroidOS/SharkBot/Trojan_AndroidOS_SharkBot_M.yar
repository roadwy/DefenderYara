
rule Trojan_AndroidOS_SharkBot_M{
	meta:
		description = "Trojan:AndroidOS/SharkBot.M,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 63 61 6e 41 70 70 49 6e 73 74 61 6c 6c 41 63 74 69 76 69 74 79 4f 6b } //01 00 
		$a_01_1 = {57 49 4c 4c 20 4b 49 4c 4c } //02 00 
		$a_01_2 = {4c 63 6f 6d 2f 6d 62 6b 72 69 73 74 69 6e 65 38 2f 63 6c 65 61 6e 6d 61 73 74 65 72 } //01 00 
		$a_01_3 = {31 32 33 34 35 36 37 38 39 30 71 77 65 72 74 79 75 69 6f 70 6c 6b 6a 68 67 66 64 73 61 7a 78 63 76 62 6e 6d } //00 00 
	condition:
		any of ($a_*)
 
}