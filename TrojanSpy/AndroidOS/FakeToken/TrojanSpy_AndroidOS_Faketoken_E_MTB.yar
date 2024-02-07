
rule TrojanSpy_AndroidOS_Faketoken_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Faketoken.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 63 61 6c 63 75 6c 61 74 6f 72 } //05 00  Lcom/android/calculator
		$a_01_1 = {4c 63 6f 6d 2f 61 7a 69 61 6e 61 6d 65 73 2f 66 6f 72 6f 6e 65 79 68 61 72 } //01 00  Lcom/azianames/foroneyhar
		$a_01_2 = {69 73 41 64 6d 69 6e 41 63 74 69 76 65 } //01 00  isAdminActive
		$a_01_3 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //01 00  setComponentEnabledSetting
		$a_01_4 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //00 00  sendTextMessage
	condition:
		any of ($a_*)
 
}