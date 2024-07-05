
rule TrojanSpy_AndroidOS_SmsThief_BE_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BE!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 61 64 41 6e 64 55 70 6c 6f 61 64 53 4d 53 } //01 00  readAndUploadSMS
		$a_01_1 = {75 70 6c 6f 61 64 44 61 74 61 54 6f 46 69 72 65 73 74 6f 72 65 } //01 00  uploadDataToFirestore
		$a_01_2 = {2f 4d 65 73 73 61 67 65 73 53 65 72 76 69 63 65 } //01 00  /MessagesService
		$a_01_3 = {75 70 6c 6f 61 64 4d 65 73 73 61 67 65 73 } //00 00  uploadMessages
	condition:
		any of ($a_*)
 
}