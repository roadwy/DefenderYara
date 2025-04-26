
rule TrojanSpy_AndroidOS_SmsThief_BB_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {6f 72 67 2e 61 6e 64 72 6f 69 64 2e 73 79 73 } //1 org.android.sys
		$a_00_1 = {74 73 79 73 74 65 6d 5f 75 70 64 61 74 65 2e 61 70 6b } //1 tsystem_update.apk
		$a_00_2 = {61 70 70 73 2e 64 61 72 6b 63 6c 75 62 2e 6e 65 74 2f 72 65 71 75 65 73 74 2f } //1 apps.darkclub.net/request/
		$a_00_3 = {55 50 44 41 54 45 5f 50 41 54 54 45 52 4e 53 } //1 UPDATE_PATTERNS
		$a_00_4 = {72 65 6d 6f 76 65 41 63 74 69 76 65 41 64 6d 69 6e } //1 removeActiveAdmin
		$a_00_5 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getMessageBody
		$a_00_6 = {38 34 37 32 39 37 34 36 30 39 30 32 } //1 847297460902
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}