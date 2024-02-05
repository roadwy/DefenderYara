
rule Trojan_AndroidOS_Fakemoney_C{
	meta:
		description = "Trojan:AndroidOS/Fakemoney.C,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 68 6f 73 6c 65 6e 61 6c 6f 74 2e 63 6f 6c 70 69 73 } //01 00 
		$a_01_1 = {68 6f 70 73 79 2e 69 6e 66 6f 2f 64 65 72 74 2e 70 68 70 } //01 00 
		$a_01_2 = {4f 78 70 74 79 76 79 6b 65 2e 73 65 74 74 69 6e 67 73 } //01 00 
		$a_01_3 = {5a 48 4a 6c 59 57 31 73 59 57 35 6b 61 57 46 75 4c 6d 6c 75 5a 6d 38 76 59 32 56 36 61 79 35 77 61 48 41 } //01 00 
		$a_01_4 = {48 67 76 6f 65 79 68 6e 63 } //01 00 
		$a_01_5 = {59 76 63 6b 61 6e 6b } //00 00 
	condition:
		any of ($a_*)
 
}