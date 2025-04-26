
rule Trojan_AndroidOS_SpyAgent_Q{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.Q,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 49 6e 42 6f 78 4d 53 47 5f 46 69 6c 74 65 72 5f 73 70 65 6e 74 } //2 GetInBoxMSG_Filter_spent
		$a_01_1 = {52 65 67 69 73 74 65 72 52 65 63 65 69 76 65 72 53 6d 73 } //2 RegisterReceiverSms
		$a_01_2 = {53 61 76 65 5f 66 69 72 73 74 5f 72 75 6e } //2 Save_first_run
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}