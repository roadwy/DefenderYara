
rule TrojanSpy_AndroidOS_GoatRAT_B{
	meta:
		description = "TrojanSpy:AndroidOS/GoatRAT.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 70 69 2e 67 6f 61 74 72 61 74 2e 63 6f 6d 3a 33 30 30 38 2f 75 73 65 72 73 2f } //02 00  api.goatrat.com:3008/users/
		$a_01_1 = {53 63 72 65 65 6e 53 68 61 72 69 6e 67 53 65 72 76 69 63 65 20 67 6f 74 20 63 6f 6d 6d 61 6e 64 3a } //01 00  ScreenSharingService got command:
		$a_01_2 = {47 6f 61 74 52 61 74 2e 63 6f 6d 20 2d 20 52 65 6d 6f 74 65 20 41 63 63 65 73 73 } //01 00  GoatRat.com - Remote Access
		$a_01_3 = {4c 63 6f 6d 2f 67 6f 61 74 6d 77 2f 63 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e 2f 53 65 72 76 65 72 } //01 00  Lcom/goatmw/communication/Server
		$a_01_4 = {67 6f 61 74 52 61 74 20 2d 20 72 65 6d 6f 74 65 20 61 63 63 65 73 73 } //00 00  goatRat - remote access
	condition:
		any of ($a_*)
 
}