
rule Trojan_AndroidOS_SmsAgent_AH{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.AH,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 45 59 5f 54 45 53 54 5f 54 4f 54 41 4c 5f 43 4f 4e 56 45 52 53 41 54 49 4f 4e } //2 KEY_TEST_TOTAL_CONVERSATION
		$a_01_1 = {2f 70 72 6f 64 75 63 74 69 6e 66 6f 2f 61 6c 72 65 61 64 79 5f 73 65 6e 64 } //2 /productinfo/already_send
		$a_01_2 = {41 43 54 49 4f 4e 5f 4d 45 53 53 41 47 45 5f 53 45 4e 44 5f 41 4c 52 45 41 44 59 } //2 ACTION_MESSAGE_SEND_ALREADY
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}