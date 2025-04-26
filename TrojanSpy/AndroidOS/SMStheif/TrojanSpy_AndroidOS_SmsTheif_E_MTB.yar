
rule TrojanSpy_AndroidOS_SmsTheif_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsTheif.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 53 6d 73 4c 6f 67 67 65 72 } //1 appSmsLogger
		$a_01_1 = {73 65 6e 64 6d 75 6c 74 69 73 6d 73 } //1 sendmultisms
		$a_01_2 = {4c 69 67 68 74 5a 65 72 30 } //1 LightZer0
		$a_01_3 = {73 61 6a 6a 61 64 34 35 38 30 } //1 sajjad4580
		$a_01_4 = {55 70 6c 6f 61 64 53 6d 73 } //1 UploadSms
		$a_01_5 = {73 65 6e 64 4d 75 6c 74 69 70 61 72 74 54 65 78 74 53 4d 53 } //1 sendMultipartTextSMS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}