
rule TrojanSpy_AndroidOS_Mlasdl_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Mlasdl.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 41 63 74 69 76 69 74 79 48 69 64 65 4f 72 4e 6f 74 } //01 00  mainActivityHideOrNot
		$a_01_1 = {72 65 63 6f 72 64 41 6d 72 53 74 61 72 74 } //01 00  recordAmrStart
		$a_01_2 = {63 6f 75 6e 74 53 6d 73 42 79 53 74 61 72 74 49 64 } //01 00  countSmsByStartId
		$a_01_3 = {67 65 74 51 51 56 6f 69 63 65 73 46 69 6c 65 49 6e 66 6f } //00 00  getQQVoicesFileInfo
	condition:
		any of ($a_*)
 
}