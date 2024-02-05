
rule TrojanSpy_AndroidOS_SmsThief_Z_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.Z!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 70 70 2f 64 77 75 72 69 61 6e 7a 73 32 33 } //01 00 
		$a_01_1 = {53 65 6e 64 53 6d 73 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_2 = {64 75 72 69 61 6e 6b 69 6e 67 2e 6d 79 64 69 76 65 61 70 70 2e 6f 6e 6c 69 6e 65 } //01 00 
		$a_01_3 = {61 6e 64 72 6f 69 64 5f 61 73 73 65 74 2f 69 70 61 79 46 50 58 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_SmsThief_Z_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.Z!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 61 73 5f 73 65 6e 64 5f 70 68 6f 6e 65 5f 69 6e 66 6f } //01 00 
		$a_00_1 = {6c 61 73 74 5f 64 65 6c 65 74 65 5f 73 6d 73 5f 74 69 6d 65 } //01 00 
		$a_00_2 = {68 61 73 5f 73 65 6e 64 5f 63 6f 6e 74 61 63 74 73 } //01 00 
		$a_00_3 = {63 6f 6d 2f 70 68 6f 6e 65 2f 73 74 6f 70 2f 61 63 74 69 76 69 74 79 } //01 00 
		$a_00_4 = {68 61 73 5f 73 65 6e 64 5f 6d 65 73 73 61 67 65 } //01 00 
		$a_00_5 = {73 65 6e 64 5f 65 6d 61 69 6c 5f 70 77 64 } //01 00 
		$a_00_6 = {68 61 73 5f 64 65 6c 65 74 65 5f 6d 65 73 73 61 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}