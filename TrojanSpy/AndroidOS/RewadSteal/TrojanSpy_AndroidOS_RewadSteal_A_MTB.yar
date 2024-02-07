
rule TrojanSpy_AndroidOS_RewadSteal_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewadSteal.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 63 6f 6d 2f 52 65 77 61 72 64 73 2f 90 02 10 2f 61 70 69 43 6f 6e 74 72 6f 6c 6c 65 72 90 00 } //01 00 
		$a_00_1 = {2f 72 6f 6f 74 2f 61 70 69 2f 75 73 65 72 2f 73 74 65 70 31 } //01 00  /root/api/user/step1
		$a_00_2 = {2f 72 6f 6f 74 2f 61 70 69 2f 75 73 65 72 2f 73 6d 73 } //01 00  /root/api/user/sms
		$a_00_3 = {4b 45 59 5f 45 54 55 53 45 52 4e 41 4d 45 } //01 00  KEY_ETUSERNAME
		$a_00_4 = {61 64 64 41 75 74 6f 53 74 61 72 74 75 70 } //01 00  addAutoStartup
		$a_00_5 = {53 6d 73 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //00 00  SmsBroadcastReceiver
	condition:
		any of ($a_*)
 
}