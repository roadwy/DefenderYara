
rule TrojanSpy_AndroidOS_Ssmsp_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ssmsp.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 6f 63 61 74 69 6f 6e 4c 6f 67 67 65 72 53 65 72 76 69 63 65 } //1 LocationLoggerService
		$a_00_1 = {53 65 6e 74 4d 65 73 73 61 67 65 47 61 74 68 65 72 } //1 SentMessageGather
		$a_00_2 = {70 6f 73 74 2e 70 68 70 } //1 post.php
		$a_00_3 = {53 4d 53 41 70 70 } //1 SMSApp
		$a_00_4 = {4c 73 6d 73 2f 75 70 6c 6f 61 64 65 72 2f 53 4d 53 4f 62 73 65 72 76 65 72 } //1 Lsms/uploader/SMSObserver
		$a_00_5 = {57 65 62 73 69 74 65 55 70 6c 6f 61 64 65 72 } //1 WebsiteUploader
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}