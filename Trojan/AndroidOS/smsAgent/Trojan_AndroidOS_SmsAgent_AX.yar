
rule Trojan_AndroidOS_SmsAgent_AX{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.AX,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 65 6e 64 61 72 2f 53 4d 53 4d 6f 6e 69 74 6f 72 } //2 calendar/SMSMonitor
		$a_01_1 = {67 65 74 53 6c 6f 74 42 79 53 75 62 73 63 72 69 70 74 69 6f 6e } //2 getSlotBySubscription
		$a_01_2 = {63 61 6c 65 6e 64 61 72 2f 53 65 6e 64 49 6e 74 72 6f } //2 calendar/SendIntro
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}