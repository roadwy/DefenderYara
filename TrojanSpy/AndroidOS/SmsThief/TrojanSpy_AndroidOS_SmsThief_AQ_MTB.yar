
rule TrojanSpy_AndroidOS_SmsThief_AQ_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AQ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 70 6c 6f 61 64 53 6d 73 46 69 6c 65 } //1 UploadSmsFile
		$a_01_1 = {63 6f 6d 2f 65 78 65 63 75 6c 61 74 6f 72 2f 73 6f 63 6b 65 74 74 65 73 74 } //1 com/execulator/sockettest
		$a_01_2 = {67 65 74 53 4d 53 4c 6f 67 73 } //1 getSMSLogs
		$a_01_3 = {67 65 74 43 6c 69 70 62 6f 61 72 64 54 65 78 74 } //1 getClipboardText
		$a_01_4 = {41 6c 6c 53 6d 73 2e 74 78 74 } //1 AllSms.txt
		$a_01_5 = {73 65 6e 64 53 6d 73 50 65 72 6d 69 73 73 69 6f 6e 43 6f 64 65 } //1 sendSmsPermissionCode
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}