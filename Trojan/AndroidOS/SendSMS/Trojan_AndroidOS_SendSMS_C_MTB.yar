
rule Trojan_AndroidOS_SendSMS_C_MTB{
	meta:
		description = "Trojan:AndroidOS/SendSMS.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 61 78 53 6d 73 } //1 maxSms
		$a_00_1 = {73 74 61 72 74 20 73 6d 73 3a 20 6d 6f 64 65 20 3d } //1 start sms: mode =
		$a_00_2 = {6d 61 78 43 6f 73 74 } //1 maxCost
		$a_00_3 = {62 6c 6f 63 6b 50 68 6f 6e 65 73 } //1 blockPhones
		$a_00_4 = {73 6d 73 54 69 6d 65 6f 75 74 } //1 smsTimeout
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}