
rule TrojanSpy_AndroidOS_Basbanke_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Basbanke.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {76 65 72 6c 61 69 65 74 69 76 69 74 79 } //01 00  verlaietivity
		$a_00_1 = {5f 61 63 73 5f 6f 6e 61 63 74 69 76 69 74 79 6e 61 6d 65 72 65 74 72 69 65 76 65 64 } //01 00  _acs_onactivitynameretrieved
		$a_00_2 = {5f 61 64 64 6f 76 65 72 6c 61 79 5f 61 } //01 00  _addoverlay_a
		$a_00_3 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 70 61 63 6b 61 67 65 69 6e 73 74 61 6c 6c 65 72 3a 69 64 2f 70 65 72 6d 69 73 73 69 6f 6e 5f 61 6c 6c 6f 77 5f 62 75 74 74 6f 6e } //01 00  com.android.packageinstaller:id/permission_allow_button
		$a_00_4 = {50 65 72 66 6f 72 6d 47 6c 6f 62 61 6c 41 63 74 69 6f 6e } //01 00  PerformGlobalAction
		$a_00_5 = {4c 65 73 2f 61 64 61 64 64 61 2f 75 6a 64 2f } //00 00  Les/adadda/ujd/
		$a_00_6 = {5d 04 00 } //00 25 
	condition:
		any of ($a_*)
 
}