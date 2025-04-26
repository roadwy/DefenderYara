
rule TrojanSpy_AndroidOS_SmsThief_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_00_0 = {62 74 6f 6f 6c 73 52 75 6e } //2 btoolsRun
		$a_00_1 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 3f 25 73 } //2 http://%s:%d/%s?%s
		$a_00_2 = {67 65 74 53 6d 73 46 72 6f 6d 50 68 6f 6e 65 } //1 getSmsFromPhone
		$a_00_3 = {53 6d 73 4f 62 73 65 72 76 65 72 } //1 SmsObserver
		$a_00_4 = {6d 6f 6e 73 65 72 76 65 72 } //1 monserver
		$a_00_5 = {70 68 6f 6e 65 6d 73 67 } //1 phonemsg
		$a_00_6 = {43 4f 44 45 5f 52 45 41 44 5f 53 4d 53 } //1 CODE_READ_SMS
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=8
 
}