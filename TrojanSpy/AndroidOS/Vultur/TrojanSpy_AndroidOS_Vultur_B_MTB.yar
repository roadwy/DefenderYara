
rule TrojanSpy_AndroidOS_Vultur_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Vultur.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 63 72 65 65 6e 52 65 63 6f 72 64 53 65 72 76 69 63 65 } //1 ScreenRecordService
		$a_01_1 = {4d 65 64 69 61 55 70 6c 6f 61 64 57 6f 72 6b 65 72 } //1 MediaUploadWorker
		$a_01_2 = {6e 73 74 61 72 74 5f 76 6e 63 } //1 nstart_vnc
		$a_01_3 = {55 6e 6c 6f 63 6b 53 63 72 65 65 6e 43 61 70 74 75 72 65 41 63 74 69 76 69 74 79 } //1 UnlockScreenCaptureActivity
		$a_01_4 = {4d 65 73 73 61 67 69 6e 67 53 65 72 76 69 63 65 } //1 MessagingService
		$a_01_5 = {4e 67 72 6f 6b 44 6f 77 6e 6c 6f 61 64 57 6f 72 6b 65 72 } //1 NgrokDownloadWorker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}