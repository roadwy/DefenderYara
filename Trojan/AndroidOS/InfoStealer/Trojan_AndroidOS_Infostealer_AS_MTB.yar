
rule Trojan_AndroidOS_Infostealer_AS_MTB{
	meta:
		description = "Trojan:AndroidOS/Infostealer.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 4c 6f 67 73 2e 4c 6f 67 73 43 6f 6e 74 65 6e 74 50 72 6f 76 69 64 65 72 2f 73 6d 73 } //1 callLogs.LogsContentProvider/sms
		$a_00_1 = {72 65 63 61 6c 63 5f 73 6d 73 } //1 recalc_sms
		$a_00_2 = {73 6d 73 5f 6f 75 74 5f 74 63 5f 6d 6f 6e 65 79 } //1 sms_out_tc_money
		$a_00_3 = {74 61 6c 6b 5f 64 75 72 61 74 69 6f 6e } //1 talk_duration
		$a_00_4 = {63 61 6c 6c 5f 66 65 65 } //1 call_fee
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}