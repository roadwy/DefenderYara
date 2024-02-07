
rule TrojanSpy_AndroidOS_Bian_A{
	meta:
		description = "TrojanSpy:AndroidOS/Bian.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {49 6e 6a 43 6f 6d 70 6f 6e 65 6e 74 42 75 69 6c 64 65 72 49 6d 70 6c } //02 00  InjComponentBuilderImpl
		$a_00_1 = {75 70 64 61 74 65 53 74 6f 63 6b 49 6e 6a 65 63 74 73 4c 69 73 74 } //01 00  updateStockInjectsList
		$a_00_2 = {69 4c 6f 63 6b 53 74 61 74 65 4c 69 73 74 65 6e 65 72 } //01 00  iLockStateListener
		$a_00_3 = {73 65 72 76 69 63 65 73 5f 70 6c 61 79 50 72 6f 74 65 63 74 } //01 00  services_playProtect
		$a_00_4 = {72 65 71 75 65 73 74 53 6d 73 41 64 6d 69 6e } //00 00  requestSmsAdmin
		$a_00_5 = {5d 04 00 } //00 f1 
	condition:
		any of ($a_*)
 
}