
rule Trojan_AndroidOS_FakeInstSms_M{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.M,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 49 57 5f 57 55 4a 5f 46 58 45 44 55 5f 44 4b 70 52 55 48 } //01 00  pIW_WUJ_FXEDU_DKpRUH
		$a_01_1 = {69 71 6c 75 56 79 42 75 64 71 43 75 } //01 00  iqluVyBudqCu
		$a_01_2 = {2f 46 78 65 64 75 44 6b 43 72 75 68 54 79 71 42 65 77 3b } //00 00  /FxeduDkCruhTyqBew;
	condition:
		any of ($a_*)
 
}