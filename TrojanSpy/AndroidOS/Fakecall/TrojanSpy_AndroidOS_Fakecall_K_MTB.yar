
rule TrojanSpy_AndroidOS_Fakecall_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecall.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {63 6f 6d 2f [0-40] 73 65 72 76 69 63 65 73 2f 43 61 6c 6c 4c 6f 67 53 65 72 76 69 63 65 } //1
		$a_01_1 = {72 65 73 74 72 69 63 74 65 64 5f 6e 75 6d 62 65 72 73 2e 64 62 } //1 restricted_numbers.db
		$a_01_2 = {75 70 6c 6f 61 64 43 61 6c 6c 4c 6f 67 } //1 uploadCallLog
		$a_01_3 = {2f 61 70 69 2f 6d 6f 62 69 6c 65 2f 63 61 6c 6c 6c 6f 67 } //1 /api/mobile/calllog
		$a_01_4 = {75 70 6c 6f 61 64 43 61 6c 6c 4c 6f 67 46 69 6c 65 } //1 uploadCallLogFile
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}