
rule TrojanSpy_AndroidOS_SAgnt_S_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,10 00 10 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 6f 72 77 61 72 64 5f 70 68 6f 6e 65 } //01 00  forward_phone
		$a_01_1 = {61 63 74 69 76 69 74 79 5f 73 6d 73 } //01 00  activity_sms
		$a_01_2 = {53 4d 53 47 65 74 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //01 00  SMSGetBroadcastReceiver
		$a_01_3 = {72 65 6c 6f 61 64 46 6f 72 77 61 72 64 20 64 61 74 61 } //0a 00  reloadForward data
		$a_00_4 = {4c 63 6f 6d 2f 63 6f 6d 70 61 6e 79 2f 63 72 65 64 69 74 } //01 00  Lcom/company/credit
		$a_01_5 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 43 6f 6c 6c 65 63 74 6f 72 53 65 72 76 69 63 65 } //01 00  NotificationCollectorService
		$a_01_6 = {75 70 4c 6f 61 64 4d 73 67 } //01 00  upLoadMsg
		$a_01_7 = {75 70 6c 6f 61 64 43 61 6c 6c 52 65 63 6f 72 64 } //00 00  uploadCallRecord
	condition:
		any of ($a_*)
 
}