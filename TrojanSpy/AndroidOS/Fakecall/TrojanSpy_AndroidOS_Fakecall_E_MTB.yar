
rule TrojanSpy_AndroidOS_Fakecall_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecall.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 70 79 2f 75 70 6c 6f 61 64 4d 6f 62 69 6c 65 53 6d 73 73 } //1 spy/uploadMobileSmss
		$a_00_1 = {75 70 6c 6f 61 64 4d 6f 62 69 6c 65 43 6f 6e 74 61 63 74 73 } //1 uploadMobileContacts
		$a_00_2 = {73 70 79 2f 64 6f 77 6e 6c 6f 61 64 4d 6f 62 69 6c 65 43 6f 6e 74 61 63 74 73 } //1 spy/downloadMobileContacts
		$a_00_3 = {73 79 6e 63 4d 6f 62 69 6c 65 43 61 6c 6c 4c 6f 67 73 } //1 syncMobileCallLogs
		$a_00_4 = {64 65 6c 65 74 65 4d 6f 62 69 6c 65 41 70 70 } //1 deleteMobileApp
		$a_00_5 = {63 6f 6d 2f 61 6d 61 6e 69 2f 62 61 73 65 } //1 com/amani/base
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}