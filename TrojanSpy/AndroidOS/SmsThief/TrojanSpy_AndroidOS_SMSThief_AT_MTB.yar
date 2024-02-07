
rule TrojanSpy_AndroidOS_SMSThief_AT_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSThief.AT!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 36 } //01 00  telegram.org/bot6
		$a_01_1 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 6d 79 61 70 70 6c 69 63 61 74 69 6f } //01 00  com/example/myapplicatio
		$a_01_2 = {2f 52 65 63 65 69 76 65 53 6d 73 } //01 00  /ReceiveSms
		$a_01_3 = {77 65 62 73 65 74 74 69 6e 67 6b 75 } //00 00  websettingku
	condition:
		any of ($a_*)
 
}