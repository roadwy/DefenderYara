
rule Trojan_AndroidOS_BankerAgent_BX{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.BX,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 6f 6d 61 6e 74 65 6c 70 72 69 7a 65 2f 53 65 72 76 69 63 65 52 65 73 74 61 72 74 65 72 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //2 com/example/omantelprize/ServiceRestarterBroadcastReceiver
		$a_01_1 = {4e 65 77 2c 20 62 65 74 74 65 72 20 61 70 70 20 65 78 70 65 72 69 61 6e 63 65 } //2 New, better app experiance
		$a_01_2 = {6f 6d 61 6e 74 65 6c 70 72 69 7a 65 2f 4f 6e 62 6f 61 72 64 69 6e 67 41 63 74 69 76 69 74 79 } //2 omantelprize/OnboardingActivity
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}