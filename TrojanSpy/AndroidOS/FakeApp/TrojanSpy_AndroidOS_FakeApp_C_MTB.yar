
rule TrojanSpy_AndroidOS_FakeApp_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeApp.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 78 69 73 70 6f 69 6e 74 63 6c 61 69 6d 2e 63 6f 2e 69 6e } //01 00  axispointclaim.co.in
		$a_00_1 = {2f 61 70 69 2f 73 69 67 6e 75 70 2e 70 68 70 2f } //01 00  /api/signup.php/
		$a_00_2 = {2f 61 70 69 2f 6d 65 73 73 61 67 65 2e 70 68 70 2f } //01 00  /api/message.php/
		$a_00_3 = {2f 61 70 69 2f 63 61 72 64 73 2e 70 68 70 2f } //01 00  /api/cards.php/
		$a_00_4 = {4b 45 59 5f 45 54 55 53 45 52 4e 41 4d 45 } //01 00  KEY_ETUSERNAME
		$a_00_5 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //01 00  getMessageBody
		$a_00_6 = {61 64 64 41 75 74 6f 53 74 61 72 74 75 70 } //00 00  addAutoStartup
	condition:
		any of ($a_*)
 
}