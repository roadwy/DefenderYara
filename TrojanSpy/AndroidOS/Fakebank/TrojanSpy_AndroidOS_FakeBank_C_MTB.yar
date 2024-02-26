
rule TrojanSpy_AndroidOS_FakeBank_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeBank.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 07 00 00 04 00 "
		
	strings :
		$a_01_0 = {61 70 70 2e 72 65 61 64 63 6f 6e 74 61 63 74 73 } //01 00  app.readcontacts
		$a_01_1 = {67 65 74 41 6c 6c 53 6d 73 } //01 00  getAllSms
		$a_01_2 = {73 79 6e 63 4d 65 73 73 } //01 00  syncMess
		$a_01_3 = {67 65 74 5f 61 64 64 72 65 73 73 } //01 00  get_address
		$a_01_4 = {67 65 74 5f 66 6f 6c 64 65 72 4e 61 6d 65 } //01 00  get_folderName
		$a_01_5 = {63 61 72 64 4e 6f 45 74 } //01 00  cardNoEt
		$a_01_6 = {63 63 76 45 74 } //00 00  ccvEt
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_FakeBank_C_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/FakeBank.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 41 64 6d 69 6e 52 65 63 69 76 65 72 } //01 00  DeAdminReciver
		$a_01_1 = {2f 61 70 70 48 6f 6d 65 2f 73 65 72 76 6c 65 74 2f 55 70 6c 6f 61 64 49 6d 61 67 65 } //01 00  /appHome/servlet/UploadImage
		$a_01_2 = {67 65 74 42 61 6e 6b 53 68 6f 72 74 42 79 70 61 63 6b } //01 00  getBankShortBypack
		$a_01_3 = {67 65 74 42 61 6e 6b 73 49 6e 66 6f } //01 00  getBanksInfo
		$a_01_4 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 50 61 63 6b 73 } //00 00  getInstalledPacks
	condition:
		any of ($a_*)
 
}