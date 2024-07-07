
rule TrojanSpy_AndroidOS_SmsThief_BG_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BG!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 69 73 74 65 72 53 6d 73 52 65 63 65 69 76 65 72 } //1 registerSmsReceiver
		$a_01_1 = {53 6d 73 46 6f 72 77 61 72 64 69 6e 67 53 65 72 76 69 63 65 } //1 SmsForwardingService
		$a_01_2 = {5f 75 70 6c 6f 61 64 44 61 74 61 54 6f 46 69 72 65 62 61 73 65 } //1 _uploadDataToFirebase
		$a_01_3 = {53 6d 73 53 65 72 76 69 63 65 } //1 SmsService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}