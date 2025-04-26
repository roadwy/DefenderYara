
rule TrojanSpy_AndroidOS_Fakecall_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecall.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 73 70 79 2f 64 6f 77 6e 6c 6f 61 64 4d 6f 62 69 6c 65 43 6f 6e 74 61 63 74 73 } //1 /spy/downloadMobileContacts
		$a_00_1 = {55 70 6c 6f 61 64 4d 6f 62 69 6c 65 44 61 74 61 48 65 6c 70 65 72 } //1 UploadMobileDataHelper
		$a_00_2 = {73 79 6e 63 4d 6f 62 69 6c 65 43 61 6c 6c 4c 6f 67 73 } //1 syncMobileCallLogs
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}