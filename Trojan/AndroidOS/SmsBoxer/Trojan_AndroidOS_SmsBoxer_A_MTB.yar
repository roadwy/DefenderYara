
rule Trojan_AndroidOS_SmsBoxer_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsBoxer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 75 2f 6a 61 62 6f 78 2f 61 6e 64 72 6f 69 64 2f 73 6d 73 62 6f 78 } //01 00 
		$a_00_1 = {41 62 73 74 72 61 63 74 53 6d 73 62 6f 78 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00 
		$a_00_2 = {4a 6f 6b 65 42 6f 78 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00 
		$a_00_3 = {4f 75 72 50 72 6f 6a 65 63 74 73 41 63 74 69 76 69 74 79 } //01 00 
		$a_00_4 = {53 65 78 42 6f 78 41 70 70 6c 69 63 61 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}