
rule TrojanSpy_AndroidOS_SmsThief_N_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_02_0 = {76 69 64 65 6f 73 6f 75 6e 64 2e 76 69 70 90 02 05 2f 4a 59 53 79 73 74 65 6d 2f 72 65 73 74 49 6e 74 2f 63 6f 6c 6c 65 63 74 2f 70 6f 73 74 4d 73 67 44 61 74 61 90 00 } //01 00 
		$a_00_1 = {2f 63 6f 6c 6c 65 63 74 2f 70 6f 73 74 44 61 74 61 } //01 00 
		$a_00_2 = {75 70 6c 6f 61 64 4d 53 47 } //01 00 
		$a_00_3 = {68 69 64 65 41 70 70 } //01 00 
		$a_00_4 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_00_5 = {63 6f 6d 2f 62 61 69 64 75 2f 6c 6f 63 61 73 73 2f 75 74 69 6c 73 } //00 00 
		$a_00_6 = {5d 04 00 00 } //ed 7f 
	condition:
		any of ($a_*)
 
}