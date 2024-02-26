
rule TrojanSpy_AndroidOS_Dabom_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Dabom.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6d 73 62 6f 6d 62 65 72 } //01 00  smsbomber
		$a_01_1 = {73 65 6e 64 32 63 6f 6e 74 61 63 74 } //01 00  send2contact
		$a_01_2 = {64 61 74 61 62 61 73 65 2e 64 62 } //01 00  database.db
		$a_01_3 = {63 6f 6d 2f 64 72 6e 75 6c 6c 2f 76 35 2f 53 6d 73 53 65 72 76 69 63 65 } //01 00  com/drnull/v5/SmsService
		$a_01_4 = {73 6d 73 5f 72 65 63 69 76 65 64 } //00 00  sms_recived
	condition:
		any of ($a_*)
 
}