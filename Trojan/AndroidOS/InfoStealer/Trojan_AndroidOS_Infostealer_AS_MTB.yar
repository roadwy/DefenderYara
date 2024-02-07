
rule Trojan_AndroidOS_Infostealer_AS_MTB{
	meta:
		description = "Trojan:AndroidOS/Infostealer.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 4c 6f 67 73 2e 4c 6f 67 73 43 6f 6e 74 65 6e 74 50 72 6f 76 69 64 65 72 2f 73 6d 73 } //01 00  callLogs.LogsContentProvider/sms
		$a_00_1 = {72 65 63 61 6c 63 5f 73 6d 73 } //01 00  recalc_sms
		$a_00_2 = {73 6d 73 5f 6f 75 74 5f 74 63 5f 6d 6f 6e 65 79 } //01 00  sms_out_tc_money
		$a_00_3 = {74 61 6c 6b 5f 64 75 72 61 74 69 6f 6e } //01 00  talk_duration
		$a_00_4 = {63 61 6c 6c 5f 66 65 65 } //00 00  call_fee
		$a_00_5 = {5d 04 00 00 } //09 8b 
	condition:
		any of ($a_*)
 
}