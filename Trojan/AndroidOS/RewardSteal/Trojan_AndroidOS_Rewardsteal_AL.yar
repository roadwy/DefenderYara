
rule Trojan_AndroidOS_Rewardsteal_AL{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AL,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 6d 61 6e 74 65 6c 70 72 69 7a 65 2f 43 61 72 64 50 61 79 6d 65 6e 74 32 } //2 omantelprize/CardPayment2
		$a_01_1 = {53 6d 73 53 65 72 76 69 63 65 3a 3a 57 61 6b 65 4c 6f 63 6b } //2 SmsService::WakeLock
		$a_01_2 = {6f 6d 61 6e 74 65 6c 70 72 69 7a 65 2f 53 65 72 76 69 63 65 52 65 73 74 61 72 74 65 72 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //2 omantelprize/ServiceRestarterBroadcastReceiver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}