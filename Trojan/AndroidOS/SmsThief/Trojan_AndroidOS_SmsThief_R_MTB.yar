
rule Trojan_AndroidOS_SmsThief_R_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsThief.R!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 6f 6e 69 63 61 70 70 } //5 com.example.onicapp
		$a_00_1 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 6e 65 77 6c 6d 72 61 } //5 com.example.newlmra
		$a_00_2 = {4d 79 53 6d 73 53 65 72 76 69 63 65 } //1 MySmsService
		$a_00_3 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getMessageBody
		$a_00_4 = {75 70 64 61 74 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 updateNotification
		$a_00_5 = {73 6d 73 4d 6f 64 65 6c } //1 smsModel
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=8
 
}