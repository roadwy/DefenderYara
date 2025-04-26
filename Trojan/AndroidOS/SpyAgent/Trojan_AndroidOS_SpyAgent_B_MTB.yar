
rule Trojan_AndroidOS_SpyAgent_B_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 53 54 41 54 55 53 } //1 SMSSTATUS
		$a_01_1 = {50 68 6f 6e 65 63 61 6c 6c 52 65 63 65 69 76 65 72 } //1 PhonecallReceiver
		$a_01_2 = {53 4d 53 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //1 SMSBroadcastReceiver
		$a_01_3 = {53 63 72 65 65 6e 53 74 61 74 75 73 } //1 ScreenStatus
		$a_01_4 = {6e 5f 6f 6e 53 74 61 72 74 43 6f 6d 6d 61 6e 64 } //1 n_onStartCommand
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}