
rule TrojanSpy_AndroidOS_Dummy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Dummy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 63 72 65 65 6e 53 68 6f 74 43 6f 6c 6c } //1 ScreenShotColl
		$a_01_1 = {4d 79 4f 62 73 65 72 76 65 72 43 61 6c 6c 4c 6f 67 73 } //1 MyObserverCallLogs
		$a_01_2 = {43 68 72 6f 6d 65 48 69 73 74 6f 72 79 43 6f 6c 6c } //1 ChromeHistoryColl
		$a_01_3 = {53 6f 63 69 61 6c 4d 65 73 73 61 67 65 73 43 6f 6c 6c 65 63 74 6f 72 } //1 SocialMessagesCollector
		$a_01_4 = {4c 63 6f 6d 2f 61 70 70 77 6f 72 6b 2e 64 75 6d 6d 79 } //1 Lcom/appwork.dummy
		$a_01_5 = {4c 63 6f 6d 2f 61 70 70 2f 70 72 6f 6a 65 63 74 61 70 70 6b 6f 72 61 } //1 Lcom/app/projectappkora
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}