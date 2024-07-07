
rule Trojan_AndroidOS_Smsfactory_AB{
	meta:
		description = "Trojan:AndroidOS/Smsfactory.AB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 49 52 53 54 5f 4f 53 5f 50 55 53 48 5f 48 41 50 50 45 4e 45 44 } //1 FIRST_OS_PUSH_HAPPENED
		$a_00_1 = {73 74 61 63 6b 73 5f 73 6d 73 5f 74 69 63 6b 5f 74 69 6d 65 5f 65 6e 64 } //1 stacks_sms_tick_time_end
		$a_01_2 = {53 4d 53 5f 53 45 4e 54 5f 43 41 50 5f 54 41 47 } //1 SMS_SENT_CAP_TAG
		$a_00_3 = {73 6d 73 5f 61 6d 6f 75 6e 74 5f 73 65 6e 64 } //1 sms_amount_send
		$a_00_4 = {67 65 74 53 74 61 63 6b 73 53 4d 53 53 65 72 76 65 72 } //1 getStacksSMSServer
		$a_00_5 = {69 73 53 4d 53 53 65 6e 74 4c 69 6d 69 74 52 65 61 63 68 65 64 } //1 isSMSSentLimitReached
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}