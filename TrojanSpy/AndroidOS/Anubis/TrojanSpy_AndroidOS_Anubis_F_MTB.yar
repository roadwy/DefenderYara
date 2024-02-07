
rule TrojanSpy_AndroidOS_Anubis_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Anubis.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 66 61 73 74 66 6c 61 73 68 6c 69 67 68 74 73 75 70 70 } //01 00  /fastflashlightsupp
		$a_01_1 = {75 72 6c 41 64 6d 69 6e 50 61 6e 65 6c } //01 00  urlAdminPanel
		$a_01_2 = {75 72 6c 44 6f 77 6e 6c 6f 61 64 41 70 70 } //01 00  urlDownloadApp
		$a_01_3 = {73 74 61 72 74 4c 6f 61 64 65 72 } //01 00  startLoader
		$a_01_4 = {69 6e 73 74 61 6c 6c 5f 6e 6f 6e 5f 6d 61 72 6b 65 74 5f 61 70 70 73 } //01 00  install_non_market_apps
		$a_01_5 = {67 65 74 4c 61 75 6e 63 68 49 6e 74 65 6e 74 46 6f 72 50 61 63 6b 61 67 65 } //00 00  getLaunchIntentForPackage
	condition:
		any of ($a_*)
 
}