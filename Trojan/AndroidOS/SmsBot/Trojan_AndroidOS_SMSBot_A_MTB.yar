
rule Trojan_AndroidOS_SMSBot_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SMSBot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 61 76 65 64 5f 61 75 74 68 5f 73 6d 73 5f 74 65 78 74 } //01 00 
		$a_00_1 = {53 6d 73 4c 6f 67 } //01 00 
		$a_00_2 = {42 4f 54 5f 49 44 } //01 00 
		$a_00_3 = {2f 62 6f 74 2e 70 68 70 } //01 00 
		$a_00_4 = {73 61 76 65 64 5f 73 6d 73 5f 6e 75 6d 62 65 72 } //01 00 
		$a_00_5 = {42 6f 74 53 65 72 76 69 63 65 } //00 00 
		$a_00_6 = {5d 04 00 00 } //c6 a5 
	condition:
		any of ($a_*)
 
}