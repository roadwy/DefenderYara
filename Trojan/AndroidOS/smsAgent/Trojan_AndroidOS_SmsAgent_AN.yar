
rule Trojan_AndroidOS_SmsAgent_AN{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.AN,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 63 75 74 6f 72 2f 54 6f 74 61 6c 52 65 63 65 69 76 65 72 } //2 executor/TotalReceiver
		$a_01_1 = {65 78 65 63 75 74 6f 72 5f 72 65 63 65 69 76 65 72 5f 6d 65 74 68 6f 64 } //2 executor_receiver_method
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}