
rule Trojan_AndroidOS_SmsThief_GH_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsThief.GH!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 73 3a 2f 2f 31 30 33 2e 38 35 2e 32 35 2e 31 36 35 3a 37 37 37 37 } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 32 31 30 33 30 32 2e 74 6f 70 2f } //01 00 
		$a_00_2 = {6b 65 65 70 73 6d 73 } //01 00 
		$a_00_3 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 69 6e 62 6f 78 } //01 00 
		$a_00_4 = {6c 61 6e 6a 69 65 5f 73 6d 73 } //01 00 
		$a_00_5 = {62 61 63 6b 75 70 20 74 72 61 63 65 20 73 75 63 63 65 73 73 } //00 00 
		$a_00_6 = {5d 04 00 00 } //ea 86 
	condition:
		any of ($a_*)
 
}