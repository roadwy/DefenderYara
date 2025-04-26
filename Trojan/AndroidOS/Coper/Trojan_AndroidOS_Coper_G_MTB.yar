
rule Trojan_AndroidOS_Coper_G_MTB{
	meta:
		description = "Trojan:AndroidOS/Coper.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6b 65 79 6c 6f 67 67 65 72 5f 73 74 61 72 74 } //1 keylogger_start
		$a_01_1 = {73 79 6e 63 5f 69 6e 6a 65 63 74 73 } //1 sync_injects
		$a_01_2 = {64 69 73 61 62 6c 65 5f 62 61 74 74 65 72 79 5f 74 61 73 6b } //1 disable_battery_task
		$a_01_3 = {6b 65 79 6c 6f 67 67 65 72 5f 74 61 73 6b } //1 keylogger_task
		$a_01_4 = {73 65 74 5f 62 6f 74 5f 6d 6f 64 65 } //1 set_bot_mode
		$a_01_5 = {61 63 74 69 76 61 74 65 5f 69 6e 6a 65 63 74 73 } //1 activate_injects
		$a_01_6 = {45 58 43 5f 53 4d 53 52 43 56 } //1 EXC_SMSRCV
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}