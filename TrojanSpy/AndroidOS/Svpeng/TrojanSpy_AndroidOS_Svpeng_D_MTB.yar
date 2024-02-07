
rule TrojanSpy_AndroidOS_Svpeng_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Svpeng.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 75 74 67 6f 69 6e 5f 50 68 6f 6e 65 } //01 00  Outgoin_Phone
		$a_01_1 = {68 69 64 65 41 70 70 } //01 00  hideApp
		$a_01_2 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //01 00  setComponentEnabledSetting
		$a_01_3 = {41 43 54 49 4f 4e 5f 53 4d 53 5f 48 49 53 54 4f 52 59 } //01 00  ACTION_SMS_HISTORY
		$a_01_4 = {63 72 65 64 43 61 72 64 4e 75 6d 62 65 72 } //01 00  credCardNumber
		$a_01_5 = {5f 4e 55 4d 42 45 52 5f 53 45 4e 44 5f 54 4f } //00 00  _NUMBER_SEND_TO
	condition:
		any of ($a_*)
 
}