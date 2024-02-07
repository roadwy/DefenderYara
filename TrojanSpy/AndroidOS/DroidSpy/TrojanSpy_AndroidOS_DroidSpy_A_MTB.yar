
rule TrojanSpy_AndroidOS_DroidSpy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/DroidSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 43 6f 6e 74 61 63 74 73 4c 69 73 74 } //01 00  postContactsList
		$a_01_1 = {72 65 61 64 57 65 62 70 61 6e 65 6c 43 6f 6d 6d 61 6e 64 73 } //01 00  readWebpanelCommands
		$a_01_2 = {64 65 6c 65 44 61 74 61 62 61 73 65 52 65 63 6f 72 64 } //01 00  deleDatabaseRecord
		$a_01_3 = {64 65 76 69 63 65 4c 61 73 74 4b 6e 6f 77 6e 4c 6f 63 61 74 69 6f 6e } //01 00  deviceLastKnownLocation
		$a_01_4 = {77 69 70 65 48 61 72 64 52 65 73 65 74 } //01 00  wipeHardReset
		$a_01_5 = {63 6f 6d 2e 73 65 63 2e 70 72 6f 76 69 64 65 72 2e 6d 6f 62 69 6c 65 2e 61 6e 64 72 6f 69 64 } //00 00  com.sec.provider.mobile.android
	condition:
		any of ($a_*)
 
}