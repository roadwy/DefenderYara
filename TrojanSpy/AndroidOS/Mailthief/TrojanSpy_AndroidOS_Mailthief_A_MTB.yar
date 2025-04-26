
rule TrojanSpy_AndroidOS_Mailthief_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Mailthief.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 73 53 70 79 43 61 6c 6c 45 6e 61 62 6c 65 64 } //1 isSpyCallEnabled
		$a_01_1 = {53 50 4f 4f 46 5f 53 4d 53 } //1 SPOOF_SMS
		$a_01_2 = {43 41 50 54 55 52 45 5f 43 41 4c 4c 4c 4f 47 } //1 CAPTURE_CALLLOG
		$a_01_3 = {52 65 6d 6f 74 65 43 61 6d 65 72 61 41 63 74 69 76 69 74 79 } //1 RemoteCameraActivity
		$a_01_4 = {43 41 4c 4c 5f 57 41 54 43 48 5f 4e 4f 54 49 46 49 43 41 54 49 4f 4e } //1 CALL_WATCH_NOTIFICATION
		$a_01_5 = {43 41 50 54 55 52 45 5f 50 41 53 53 57 4f 52 44 } //1 CAPTURE_PASSWORD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}