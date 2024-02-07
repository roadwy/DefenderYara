
rule TrojanSpy_AndroidOS_Fakecalls_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecalls.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 69 72 73 74 5f 73 63 61 6e 6e 65 72 5f 61 70 70 } //01 00  first_scanner_app
		$a_01_1 = {73 68 6f 75 6c 64 4f 76 65 72 72 69 64 65 55 72 6c 4c 6f 61 64 69 6e 67 } //01 00  shouldOverrideUrlLoading
		$a_01_2 = {69 73 53 63 61 6e 6e 69 6e 67 46 6f 72 4f 42 51 } //01 00  isScanningForOBQ
		$a_01_3 = {55 4e 4e 45 43 45 53 53 41 52 59 5f 41 55 54 4f 5f 44 45 4c 45 54 45 5f 4c 49 53 54 } //01 00  UNNECESSARY_AUTO_DELETE_LIST
		$a_01_4 = {4b 45 59 5f 49 53 5f 4a 55 4d 50 5f 54 4f 5f 43 4c 4f 53 45 5f 54 43 41 4c 4c } //01 00  KEY_IS_JUMP_TO_CLOSE_TCALL
		$a_01_5 = {43 61 6c 6c 4c 6f 67 42 65 61 6e 7b 70 68 6f 6e 65 31 3d } //00 00  CallLogBean{phone1=
	condition:
		any of ($a_*)
 
}