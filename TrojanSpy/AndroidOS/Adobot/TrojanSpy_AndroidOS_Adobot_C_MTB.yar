
rule TrojanSpy_AndroidOS_Adobot_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Adobot.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6d 73 46 6f 72 63 65 55 70 6c 6f 61 64 } //01 00  smsForceUpload
		$a_01_1 = {54 72 61 6e 73 66 65 72 42 6f 74 54 61 73 6b } //01 00  TransferBotTask
		$a_01_2 = {53 6d 73 52 65 63 6f 72 64 65 72 54 61 73 6b } //00 00  SmsRecorderTask
	condition:
		any of ($a_*)
 
}