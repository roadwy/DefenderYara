
rule TrojanSpy_AndroidOS_SmsThief_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //01 00 
		$a_00_1 = {62 61 74 74 72 79 72 65 61 6c 72 61 74 } //01 00 
		$a_00_2 = {61 6c 6c 61 70 70 2e 7a 69 70 } //01 00 
		$a_00_3 = {61 6c 6c 73 6d 73 2e 7a 69 70 } //01 00 
		$a_00_4 = {2f 73 65 6e 64 61 6c 6c 73 6d 73 } //01 00 
		$a_00_5 = {75 6c 74 72 61 5f 68 69 64 65 69 63 6f 6e } //00 00 
		$a_00_6 = {5d 04 00 } //00 6b 
	condition:
		any of ($a_*)
 
}