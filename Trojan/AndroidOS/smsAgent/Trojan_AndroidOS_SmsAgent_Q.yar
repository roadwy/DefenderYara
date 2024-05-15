
rule Trojan_AndroidOS_SmsAgent_Q{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.Q,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6c 6f 74 75 73 65 65 64 5f 6a 72 5f 6f 6b } //02 00  lotuseed_jr_ok
		$a_01_1 = {6c 6f 74 75 73 65 65 64 5f 75 70 64 61 74 65 5f 6a 72 } //02 00  lotuseed_update_jr
		$a_01_2 = {6c 6f 74 75 73 65 65 64 5f 6a 72 5f 61 6c 72 65 61 64 79 5f 6c 61 74 65 73 74 } //00 00  lotuseed_jr_already_latest
	condition:
		any of ($a_*)
 
}