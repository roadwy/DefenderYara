
rule TrojanSpy_AndroidOS_DaazBot_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/DaazBot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6d 73 52 65 70 6f 73 69 74 6f 72 79 } //1 SmsRepository
		$a_01_1 = {73 63 72 65 65 6e 5f 72 65 61 64 65 72 } //1 screen_reader
		$a_01_2 = {6f 6e 55 70 6c 6f 61 64 4c 6f 67 73 43 6c 69 63 6b } //1 onUploadLogsClick
		$a_01_3 = {4c 63 6f 6d 2f 64 61 61 7a 62 6f 74 } //1 Lcom/daazbot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}