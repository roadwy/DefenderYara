
rule TrojanSpy_AndroidOS_HiddenApp_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/HiddenApp.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {61 63 74 69 76 69 74 79 5f 6b 65 79 70 72 65 73 73 } //1 activity_keypress
		$a_00_1 = {74 69 6d 65 72 63 61 6c 6c 73 } //1 timercalls
		$a_00_2 = {53 49 4d 2e 54 6f 6f 6c 6b 69 74 73 } //1 SIM.Toolkits
		$a_00_3 = {46 69 6e 64 42 79 4d 61 69 6c } //1 FindByMail
		$a_00_4 = {62 6f 74 20 74 6f 6b 65 6e 2e 74 78 74 } //1 bot token.txt
		$a_00_5 = {53 6d 73 49 6e 74 65 72 63 65 70 74 6f 72 } //1 SmsInterceptor
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}