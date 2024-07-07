
rule TrojanSpy_AndroidOS_GoldDream_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GoldDream.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 48 4f 4e 45 43 41 4c 4c 5f 46 49 4c 45 5f 4e 41 4d 45 } //1 PHONECALL_FILE_NAME
		$a_01_1 = {53 4d 53 5f 46 49 4c 45 5f 4e 41 4d 45 } //1 SMS_FILE_NAME
		$a_01_2 = {69 6e 63 6f 6d 65 5f 70 68 6f 6e 65 4e 75 6d 62 65 72 } //1 income_phoneNumber
		$a_01_3 = {49 73 57 61 74 63 68 53 6d 73 } //1 IsWatchSms
		$a_01_4 = {75 70 6c 6f 61 64 41 6c 6c 46 69 6c 65 73 } //1 uploadAllFiles
		$a_01_5 = {4b 45 59 5f 5a 4a 5f 55 50 4c 4f 41 44 57 41 54 43 48 46 49 4c 45 53 } //1 KEY_ZJ_UPLOADWATCHFILES
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}