
rule Trojan_AndroidOS_Ksapp_AS_MTB{
	meta:
		description = "Trojan:AndroidOS/Ksapp.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 75 6e 20 69 6e 20 65 6d 75 6c 61 74 6f 72 } //01 00 
		$a_00_1 = {6c 61 73 74 46 6f 75 72 4f 66 41 63 63 6f 75 6e 74 4e 75 6d 62 65 72 } //01 00 
		$a_00_2 = {46 75 6e 64 69 6e 67 50 6c 61 6e 73 } //01 00 
		$a_00_3 = {50 61 79 50 61 6c 41 63 74 69 76 69 74 79 } //01 00 
		$a_00_4 = {2f 44 6f 6d 6f 62 41 70 70 44 6f 77 6e 6c 6f 61 64 2f } //01 00 
		$a_00_5 = {70 61 79 5f 63 6f 69 6e } //00 00 
		$a_00_6 = {5d 04 00 00 } //f1 8b 
	condition:
		any of ($a_*)
 
}