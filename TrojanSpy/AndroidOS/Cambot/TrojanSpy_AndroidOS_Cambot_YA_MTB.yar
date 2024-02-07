
rule TrojanSpy_AndroidOS_Cambot_YA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Cambot.YA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 90 02 15 2f 70 72 69 76 61 74 65 2f 61 64 64 5f 6c 6f 67 2e 70 68 70 90 00 } //01 00 
		$a_01_1 = {61 6e 75 5f 62 69 73 70 75 6c 6f 2e 61 70 70 } //01 00  anu_bispulo.app
		$a_01_2 = {53 6d 73 4d 65 73 73 61 67 65 2e 63 72 65 61 74 65 46 72 6f 6d 50 64 75 } //01 00  SmsMessage.createFromPdu
		$a_00_3 = {53 65 74 4a 61 76 61 53 63 72 69 70 74 45 6e 61 62 6c 65 64 } //01 00  SetJavaScriptEnabled
		$a_00_4 = {5f 43 4d 4f 58 43 64 56 54 4a 52 45 42 } //00 00  _CMOXCdVTJREB
	condition:
		any of ($a_*)
 
}