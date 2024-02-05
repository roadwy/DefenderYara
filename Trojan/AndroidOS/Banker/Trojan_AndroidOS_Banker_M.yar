
rule Trojan_AndroidOS_Banker_M{
	meta:
		description = "Trojan:AndroidOS/Banker.M,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 45 59 5f 54 45 4c 45 43 4f 4d 53 5f 4e 41 4d 45 } //01 00 
		$a_00_1 = {78 30 30 30 30 6d 63 } //01 00 
		$a_00_2 = {4b 45 59 5f 4c 41 54 45 53 54 5f 53 4d 53 5f 54 49 4d 45 } //01 00 
		$a_00_3 = {6d 57 69 6e 64 6f 77 49 73 53 68 6f 77 69 6e 67 3a } //01 00 
		$a_00_4 = {62 6c 61 63 6b 4c 69 73 74 20 55 70 64 61 74 65 20 6e 75 6d 62 65 72 3a } //00 00 
		$a_00_5 = {5d 04 00 } //00 0c 
	condition:
		any of ($a_*)
 
}