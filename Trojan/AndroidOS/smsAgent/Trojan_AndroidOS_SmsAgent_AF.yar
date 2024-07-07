
rule Trojan_AndroidOS_SmsAgent_AF{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.AF,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 63 6b 73 5f 73 6d 73 5f 64 61 69 6c 79 5f 63 61 70 } //2 stacks_sms_daily_cap
		$a_01_1 = {53 4d 53 5f 53 45 4e 54 5f 53 54 41 52 54 5f 54 41 47 } //2 SMS_SENT_START_TAG
		$a_01_2 = {73 74 61 63 6b 73 5f 73 6d 73 5f 74 69 63 6b 5f 74 69 6d 65 5f 65 6e 64 } //2 stacks_sms_tick_time_end
		$a_01_3 = {73 6d 73 5f 61 6d 6f 75 6e 74 5f 73 65 6e 64 } //2 sms_amount_send
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}