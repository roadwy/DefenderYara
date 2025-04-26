
rule TrojanSpy_AndroidOS_Fmond_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fmond.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_00_0 = {52 65 6d 6f 74 65 43 61 6d 65 72 61 41 63 74 69 76 69 74 79 } //1 RemoteCameraActivity
		$a_00_1 = {69 73 53 70 79 45 6e 61 62 6c 65 64 } //1 isSpyEnabled
		$a_00_2 = {65 6e 61 62 6c 65 53 70 79 43 61 6c 6c 4f 72 49 6e 74 65 72 63 65 70 74 43 61 6c 6c } //1 enableSpyCallOrInterceptCall
		$a_00_3 = {4c 63 6f 6d 2f 76 76 74 2f 63 61 6c 6c 6d 61 6e 61 67 65 72 2f 72 65 66 2f 63 6f 6d 6d 61 6e 64 2f 52 65 6d 6f 74 65 41 64 64 4d 6f 6e 69 74 6f 72 } //1 Lcom/vvt/callmanager/ref/command/RemoteAddMonitor
		$a_00_4 = {43 61 6c 6c 4c 6f 67 43 61 70 74 75 72 65 } //1 CallLogCapture
		$a_00_5 = {43 68 72 6f 6d 65 43 61 70 74 75 72 65 } //1 ChromeCapture
		$a_00_6 = {47 6d 61 69 6c 43 61 70 74 75 72 65 } //1 GmailCapture
		$a_00_7 = {52 65 6d 6f 74 65 41 64 64 53 6d 73 49 6e 74 65 72 63 65 70 74 } //1 RemoteAddSmsIntercept
		$a_00_8 = {2f 63 61 6c 6c 6d 6f 6e 2e 7a 69 70 } //1 /callmon.zip
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=6
 
}