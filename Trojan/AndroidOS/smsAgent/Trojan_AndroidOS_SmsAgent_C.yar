
rule Trojan_AndroidOS_SmsAgent_C{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 59 53 4d 53 50 61 79 65 72 } //01 00  SYSMSPayer
		$a_00_1 = {53 4d 53 53 65 6e 64 53 74 61 74 65 52 65 63 65 69 76 65 72 } //01 00  SMSSendStateReceiver
		$a_00_2 = {70 61 79 5f 69 73 5f 73 65 72 76 65 72 5f 72 65 63 6f 72 64 } //01 00  pay_is_server_record
		$a_00_3 = {69 73 43 72 65 61 74 65 64 53 68 6f 72 63 75 74 } //00 00  isCreatedShorcut
		$a_00_4 = {5d 04 00 } //00 4a 
	condition:
		any of ($a_*)
 
}