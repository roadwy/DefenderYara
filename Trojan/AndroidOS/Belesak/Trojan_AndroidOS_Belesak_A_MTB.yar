
rule Trojan_AndroidOS_Belesak_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Belesak.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 72 6d 77 72 2e 73 68 } //01 00 
		$a_00_1 = {49 50 43 5f 46 49 4c 45 44 41 54 41 5f 44 55 4d 50 } //01 00 
		$a_00_2 = {2f 73 79 73 74 65 6d 2f 65 74 63 2f 78 72 65 62 75 69 6c 64 2e 73 68 } //01 00 
		$a_00_3 = {49 50 43 5f 41 50 50 44 41 54 41 5f 53 43 52 45 45 4e 53 48 4f 54 } //01 00 
		$a_00_4 = {49 50 43 5f 43 4f 4d 4d 41 4e 44 5f 50 54 52 41 43 45 5f 48 4f 4f 4b } //00 00 
	condition:
		any of ($a_*)
 
}