
rule TrojanSpy_AndroidOS_SMSSpy_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {61 6c 70 68 61 20 76 69 72 75 73 20 68 61 73 20 69 6e 73 74 61 6c 6c 65 64 20 74 6f 20 76 69 63 74 69 6f 6d 20 70 68 6f 6e 65 } //1 alpha virus has installed to victiom phone
		$a_00_1 = {5f 74 6f 6b 65 6e 62 6f 74 } //1 _tokenbot
		$a_00_2 = {2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //1 /api.telegram.org/bot
		$a_00_3 = {2f 73 65 6e 64 6d 65 73 73 61 67 65 } //1 /sendmessage
		$a_00_4 = {62 61 63 6b 67 72 6f 75 6e 64 20 72 75 6e 6e 65 64 } //1 background runned
		$a_00_5 = {53 4d 53 49 6e 74 65 72 63 65 70 74 6f 72 } //1 SMSInterceptor
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}