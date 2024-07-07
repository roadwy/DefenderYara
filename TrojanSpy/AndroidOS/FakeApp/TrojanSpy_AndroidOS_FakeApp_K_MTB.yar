
rule TrojanSpy_AndroidOS_FakeApp_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeApp.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_00_0 = {6a 6b 77 65 62 32 35 35 2e 74 6f 70 2f 61 70 69 2f } //10 jkweb255.top/api/
		$a_00_1 = {72 65 63 75 72 72 65 6e 63 65 53 65 72 76 69 63 65 } //1 recurrenceService
		$a_00_2 = {72 65 63 75 72 72 65 6e 63 65 49 6d 67 53 65 72 76 69 63 65 } //1 recurrenceImgService
		$a_00_3 = {67 65 74 43 61 6c 6c 4c 6f 67 } //1 getCallLog
		$a_00_4 = {67 65 74 43 6f 6e 74 61 63 74 73 } //1 getContacts
		$a_00_5 = {67 65 74 53 6d 73 } //1 getSms
		$a_00_6 = {73 65 6e 64 50 6f 73 74 49 6d 67 } //1 sendPostImg
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=13
 
}