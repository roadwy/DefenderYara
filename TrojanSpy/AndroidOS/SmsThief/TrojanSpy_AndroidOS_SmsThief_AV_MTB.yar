
rule TrojanSpy_AndroidOS_SmsThief_AV_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AV!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 48 69 64 65 52 65 63 65 69 76 65 72 } //01 00  AutoHideReceiver
		$a_01_1 = {63 6f 6d 2f 72 61 74 2f 6c 6f 67 67 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72 } //01 00  com/rat/logger/SmsReceiver
		$a_01_2 = {53 65 6e 64 43 6f 6e 74 61 63 74 54 6f 53 65 72 76 65 72 } //01 00  SendContactToServer
		$a_01_3 = {61 70 70 73 6d 73 6c 6f 67 67 65 72 } //01 00  appsmslogger
		$a_01_4 = {53 6d 6d 73 44 61 74 61 62 61 73 65 } //00 00  SmmsDatabase
	condition:
		any of ($a_*)
 
}