
rule Trojan_AndroidOS_Piom_C{
	meta:
		description = "Trojan:AndroidOS/Piom.C,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 54 77 6f 48 65 61 64 } //1 setTwoHead
		$a_01_1 = {73 68 6f 77 43 61 6c 6c 4c 6f 67 } //1 showCallLog
		$a_01_2 = {73 74 61 72 74 54 68 69 72 64 70 61 72 74 79 41 70 70 } //1 startThirdpartyApp
		$a_01_3 = {73 75 70 70 6f 72 74 53 70 65 65 64 79 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 supportSpeedyClassLoader
		$a_01_4 = {75 72 6c 48 74 74 70 55 70 6c 6f 61 64 46 69 6c 65 } //1 urlHttpUploadFile
		$a_01_5 = {77 72 69 74 65 53 4d 53 4d 65 73 73 61 67 65 54 6f 49 6e 62 6f 78 } //1 writeSMSMessageToInbox
		$a_01_6 = {42 4c 4f 43 4b 45 44 5f 53 4d 53 5f 53 4f 55 4e 44 5f 4e 4f 54 49 46 49 43 41 54 49 4f 4e } //1 BLOCKED_SMS_SOUND_NOTIFICATION
		$a_01_7 = {46 52 4f 4d 5f 42 4c 41 43 4b 5f 4c 49 53 54 } //1 FROM_BLACK_LIST
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}