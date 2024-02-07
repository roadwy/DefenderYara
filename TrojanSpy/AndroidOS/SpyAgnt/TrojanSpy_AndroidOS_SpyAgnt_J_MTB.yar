
rule TrojanSpy_AndroidOS_SpyAgnt_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgnt.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 78 65 63 75 74 65 57 69 74 68 53 68 65 6c 6c } //01 00  executeWithShell
		$a_00_1 = {65 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 } //01 00  executeCommand
		$a_00_2 = {6b 69 6c 6c 5f 70 72 6f 63 65 73 73 } //01 00  kill_process
		$a_00_3 = {63 72 65 61 74 65 53 63 72 65 65 6e 43 61 70 74 75 72 65 49 6e 74 65 6e 74 } //01 00  createScreenCaptureIntent
		$a_00_4 = {63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 63 72 75 73 74 2f 71 74 } //00 00  com/android/crust/qt
	condition:
		any of ($a_*)
 
}