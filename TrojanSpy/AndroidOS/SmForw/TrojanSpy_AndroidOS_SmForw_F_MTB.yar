
rule TrojanSpy_AndroidOS_SmForw_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 4c 6f 67 67 65 72 } //1 CallLogger
		$a_01_1 = {49 4e 54 45 52 43 45 50 54 5f 53 4d 53 } //1 INTERCEPT_SMS
		$a_01_2 = {63 6f 6d 2f 70 68 6f 6e 65 2f 63 61 6c 6c 63 6f 72 65 78 79 } //1 com/phone/callcorexy
		$a_01_3 = {67 65 74 55 70 6c 6f 61 64 53 6d 73 43 6f 75 6e 74 } //1 getUploadSmsCount
		$a_01_4 = {64 65 6c 65 74 65 41 6c 6c 43 61 6c 6c 52 65 63 6f 72 64 48 69 73 74 6f 72 79 } //1 deleteAllCallRecordHistory
		$a_01_5 = {49 4e 54 45 52 43 45 50 54 5f 41 4c 4c 5f 50 48 4f 4e 45 } //1 INTERCEPT_ALL_PHONE
		$a_01_6 = {6d 4d 79 43 61 6c 6c 43 6f 6e 74 65 6e 74 4f 62 73 65 72 76 65 72 } //1 mMyCallContentObserver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}