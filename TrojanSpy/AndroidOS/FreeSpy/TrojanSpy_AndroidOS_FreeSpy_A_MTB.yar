
rule TrojanSpy_AndroidOS_FreeSpy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FreeSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 72 65 65 61 6e 64 72 6f 69 64 73 70 79 2e 63 6f 6d } //1 freeandroidspy.com
		$a_01_1 = {6d 6f 64 75 6c 65 5f 6b 65 79 6c 6f 67 5f 73 74 61 74 65 5f 63 68 61 6e 67 65 } //1 module_keylog_state_change
		$a_01_2 = {70 6c 61 79 5f 70 72 6f 74 65 63 74 5f 73 74 61 74 75 73 } //1 play_protect_status
		$a_01_3 = {54 65 6c 65 67 72 61 6d 4d 65 73 73 61 67 65 4d 6f 6e 69 74 6f 72 } //1 TelegramMessageMonitor
		$a_01_4 = {53 6d 73 4d 6f 6e 69 74 6f 72 } //1 SmsMonitor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}