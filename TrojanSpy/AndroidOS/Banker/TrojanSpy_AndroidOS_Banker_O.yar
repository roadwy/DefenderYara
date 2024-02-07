
rule TrojanSpy_AndroidOS_Banker_O{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.O,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 6c 6c 5f 73 6d 73 5f 72 65 63 65 69 76 65 64 } //01 00  all_sms_received
		$a_00_1 = {44 41 54 41 5f 52 45 43 45 49 56 45 44 5f 41 4c 45 52 54 } //01 00  DATA_RECEIVED_ALERT
		$a_00_2 = {3c 3e 53 69 6c 65 6e 74 5f 64 6f 6e 65 } //01 00  <>Silent_done
		$a_00_3 = {61 6c 6c 5f 63 61 6c 6c 5f 72 65 63 65 69 76 65 64 } //01 00  all_call_received
		$a_00_4 = {3c 3e 6d 73 67 3c 3e 59 45 53 20 49 53 20 4f 4e 4c 49 4e 45 } //00 00  <>msg<>YES IS ONLINE
	condition:
		any of ($a_*)
 
}