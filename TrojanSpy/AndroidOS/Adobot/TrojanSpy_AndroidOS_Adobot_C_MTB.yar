
rule TrojanSpy_AndroidOS_Adobot_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Adobot.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6d 73 46 6f 72 63 65 55 70 6c 6f 61 64 } //1 smsForceUpload
		$a_01_1 = {54 72 61 6e 73 66 65 72 42 6f 74 54 61 73 6b } //1 TransferBotTask
		$a_01_2 = {53 6d 73 52 65 63 6f 72 64 65 72 54 61 73 6b } //1 SmsRecorderTask
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}