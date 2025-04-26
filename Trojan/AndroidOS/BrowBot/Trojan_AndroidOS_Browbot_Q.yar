
rule Trojan_AndroidOS_Browbot_Q{
	meta:
		description = "Trojan:AndroidOS/Browbot.Q,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6d 73 52 65 63 65 69 76 65 72 41 63 74 69 76 69 74 79 5f 32 31 } //2 SmsReceiverActivity_21
		$a_01_1 = {63 6f 6d 2e 62 72 6f 77 73 65 72 2e 6d 79 32 37 } //2 com.browser.my27
		$a_01_2 = {70 72 65 66 65 72 65 6e 63 65 73 4d 61 6e 61 67 65 72 5f 32 33 } //2 preferencesManager_23
		$a_01_3 = {53 6d 73 52 65 63 65 69 76 65 72 5f 32 33 } //2 SmsReceiver_23
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}