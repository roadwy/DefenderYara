
rule TrojanSpy_AndroidOS_SmsThief_Q_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 75 70 64 2f 74 61 73 6b 2e 70 68 70 } //01 00 
		$a_00_1 = {73 65 6e 64 5f 73 6d 73 5f 6e 75 6d 62 65 72 } //01 00 
		$a_00_2 = {73 65 6e 64 53 4d 53 4f 6e 54 68 65 50 68 6f 6e 65 42 6f 6f 6b } //01 00 
		$a_00_3 = {72 65 70 6f 72 74 57 69 63 68 44 61 74 61 54 61 73 6b 49 6e 6a 65 63 74 } //01 00 
		$a_00_4 = {2f 75 70 64 2f 69 6e 6a 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}