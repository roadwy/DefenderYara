
rule TrojanSpy_AndroidOS_SmsThief_U_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 4d 65 73 73 61 67 65 53 69 6c 65 6e 74 6c 79 } //1 sendMessageSilently
		$a_00_1 = {75 70 6c 6f 61 64 4d 65 73 73 61 67 65 53 69 6c 65 6e 74 6c 79 } //1 uploadMessageSilently
		$a_00_2 = {68 61 6e 64 6c 65 53 6d 73 49 6e 74 65 72 63 65 70 74 65 64 } //1 handleSmsIntercepted
		$a_00_3 = {67 65 74 50 68 6f 6e 65 4e 75 6d 62 65 72 } //1 getPhoneNumber
		$a_00_4 = {67 65 74 53 6d 73 49 6e 50 68 6f 6e 65 } //1 getSmsInPhone
		$a_00_5 = {73 65 6e 64 54 65 6c 65 70 68 6f 6e 65 49 6e 66 6f 73 } //1 sendTelephoneInfos
		$a_00_6 = {67 65 74 4d 61 69 6c 54 65 6c 65 70 68 6f 6e 65 49 6e 66 6f } //1 getMailTelephoneInfo
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}