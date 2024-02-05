
rule TrojanSpy_AndroidOS_SmsThief_AN_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AN!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 73 65 72 76 6c 65 74 43 6f 6e 74 61 63 74 } //01 00 
		$a_01_1 = {71 75 65 72 79 49 6e 62 6f 78 53 6d 73 } //01 00 
		$a_01_2 = {69 6e 62 6f 78 43 6f 6e 74 61 63 74 4c 69 73 74 } //01 00 
		$a_01_3 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //01 00 
		$a_01_4 = {73 6d 73 4c 69 73 74 } //01 00 
		$a_01_5 = {67 65 74 46 6f 72 77 61 72 64 4e 75 6d 62 65 72 } //0a 00 
		$a_01_6 = {4c 63 6f 6d 2f 70 72 6f 5f 6e 65 77 2f 77 77 77 2f 50 68 6f 6e 65 53 65 72 76 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}