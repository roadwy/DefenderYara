
rule TrojanSpy_AndroidOS_Gasms_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Gasms.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 67 61 6d 62 6c 65 72 2f 53 65 6e 64 53 4d 53 2f 53 4d 53 4d 6f 6e 69 74 6f 72 } //01 00  Lcom/gambler/SendSMS/SMSMonitor
		$a_01_1 = {53 4d 53 4d 6f 6e 69 74 6f 72 4e 75 6d } //01 00  SMSMonitorNum
		$a_01_2 = {53 4d 53 4d 6f 6e 69 74 6f 72 45 6d 61 69 6c } //01 00  SMSMonitorEmail
		$a_00_3 = {69 6e 63 6f 6d 69 6e 67 4e 75 6d 62 65 72 20 3d 3d } //01 00  incomingNumber ==
		$a_01_4 = {53 4d 53 4d 6f 6e 69 74 6f 72 43 6f 75 6e 74 } //00 00  SMSMonitorCount
		$a_00_5 = {5d 04 00 00 } //83 93 
	condition:
		any of ($a_*)
 
}