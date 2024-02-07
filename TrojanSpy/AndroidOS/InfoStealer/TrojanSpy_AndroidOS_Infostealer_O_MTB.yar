
rule TrojanSpy_AndroidOS_Infostealer_O_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Infostealer.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6e 66 69 67 5f 73 65 6e 64 5f 6d 61 69 6c } //01 00  config_send_mail
		$a_00_1 = {67 65 74 50 68 6f 6e 65 5f 6e 75 6d 62 65 72 } //01 00  getPhone_number
		$a_00_2 = {73 6d 73 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 } //01 00  sms_phone_number
		$a_00_3 = {73 65 6e 64 53 6d 73 44 61 74 61 } //01 00  sendSmsData
		$a_00_4 = {73 6d 73 5f 69 64 5f 63 75 72 72 65 6e 74 } //01 00  sms_id_current
		$a_00_5 = {53 6d 73 49 6e 66 6f } //00 00  SmsInfo
	condition:
		any of ($a_*)
 
}