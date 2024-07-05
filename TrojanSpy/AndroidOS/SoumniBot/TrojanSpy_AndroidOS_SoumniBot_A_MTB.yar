
rule TrojanSpy_AndroidOS_SoumniBot_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SoumniBot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 20 73 6d 73 20 70 68 6f 6e 65 4e 75 6d 62 65 72 } //01 00  send sms phoneNumber
		$a_01_1 = {73 65 6e 64 20 73 6d 73 20 6d 65 73 73 61 67 65 } //01 00  send sms message
		$a_01_2 = {61 70 70 40 70 68 6f 6e 65 31 2d 73 70 79 2e 63 6f 6d } //01 00  app@phone1-spy.com
		$a_01_3 = {2f 6d 71 74 74 } //01 00  /mqtt
		$a_01_4 = {6d 61 69 6e 73 69 74 65 } //00 00  mainsite
	condition:
		any of ($a_*)
 
}