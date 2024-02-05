
rule TrojanSpy_AndroidOS_SmsThief_AK_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AK!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 72 72 61 79 4f 66 53 6d 73 4d 65 73 73 61 67 65 } //01 00 
		$a_01_1 = {4d 65 73 61 67 65 41 50 50 4c 69 63 61 74 69 6f 6e } //01 00 
		$a_01_2 = {73 65 6e 64 53 6d 73 } //01 00 
		$a_01_3 = {72 65 73 67 69 73 74 65 72 } //01 00 
		$a_01_4 = {73 6d 73 48 61 6e 64 6c 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}