
rule Trojan_AndroidOS_SendSMS_C_MTB{
	meta:
		description = "Trojan:AndroidOS/SendSMS.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 61 78 53 6d 73 } //01 00  maxSms
		$a_00_1 = {73 74 61 72 74 20 73 6d 73 3a 20 6d 6f 64 65 20 3d } //01 00  start sms: mode =
		$a_00_2 = {6d 61 78 43 6f 73 74 } //01 00  maxCost
		$a_00_3 = {62 6c 6f 63 6b 50 68 6f 6e 65 73 } //01 00  blockPhones
		$a_00_4 = {73 6d 73 54 69 6d 65 6f 75 74 } //00 00  smsTimeout
	condition:
		any of ($a_*)
 
}