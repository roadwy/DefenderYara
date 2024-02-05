
rule TrojanSpy_AndroidOS_SmsThief_R_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.R!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 61 6e 61 61 70 6b } //01 00 
		$a_00_1 = {63 6f 6d 2e 4d 61 72 73 4d 61 6e } //01 00 
		$a_00_2 = {67 65 74 4c 61 73 74 53 6d 73 } //01 00 
		$a_00_3 = {68 69 64 65 41 70 70 49 63 6f 6e } //01 00 
		$a_00_4 = {74 65 73 74 2e 74 65 73 74 } //01 00 
		$a_00_5 = {73 6d 63 6f 6e 74 61 63 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}