
rule Trojan_AndroidOS_Handda_A{
	meta:
		description = "Trojan:AndroidOS/Handda.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 68 6d 6f 64 20 2d 52 20 34 37 35 35 20 2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 } //02 00 
		$a_01_1 = {4c 63 6f 6d 2f 70 68 6f 74 6f 2f 61 6e 64 72 6f 69 64 61 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 3b } //02 00 
		$a_01_2 = {65 78 5f 69 73 75 70 6c 6f 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}