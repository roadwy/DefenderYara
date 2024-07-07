
rule TrojanSpy_AndroidOS_SMSSpy_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6e 73 74 5f 72 65 67 69 73 74 65 72 5f 62 6f 74 } //1 const_register_bot
		$a_00_1 = {73 65 74 53 61 76 65 49 6e 62 6f 78 53 6d 73 } //1 setSaveInboxSms
		$a_00_2 = {43 6f 6d 61 6e 64 20 73 65 6e 64 20 73 6d 73 20 69 64 } //1 Comand send sms id
		$a_00_3 = {73 6d 73 43 6f 6e 74 72 6f 6c } //1 smsControl
		$a_00_4 = {53 65 74 20 62 6f 74 20 69 64 } //1 Set bot id
		$a_00_5 = {73 61 76 65 43 61 72 64 20 2d 20 67 65 74 49 6e 66 6f } //1 saveCard - getInfo
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}