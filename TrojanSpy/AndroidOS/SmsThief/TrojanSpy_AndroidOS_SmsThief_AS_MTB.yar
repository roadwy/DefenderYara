
rule TrojanSpy_AndroidOS_SmsThief_AS_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 63 6f 6d 6e 65 74 6f 72 67 69 6e 66 6f 2e 63 6f 6d } //01 00 
		$a_01_1 = {53 6d 73 52 65 63 65 69 76 65 72 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_2 = {63 6f 6d 2f 69 6e 74 65 72 6e 65 74 2f 77 65 62 63 68 72 6f 6d 65 } //01 00 
		$a_03_3 = {64 61 74 61 2f 69 6e 73 74 61 6c 6c 90 02 04 2e 70 68 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}