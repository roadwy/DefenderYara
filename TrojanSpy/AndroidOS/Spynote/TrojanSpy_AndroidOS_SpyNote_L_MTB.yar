
rule TrojanSpy_AndroidOS_SpyNote_L_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyNote.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {5f 63 61 6c 6c 72 5f 6c 73 6e 72 5f } //01 00  _callr_lsnr_
		$a_00_1 = {69 61 6d 77 6f 72 6b 69 6e 67 } //01 00  iamworking
		$a_00_2 = {69 73 45 6d 75 6c 61 74 6f 72 5f 31 } //01 00  isEmulator_1
		$a_00_3 = {65 6e 61 62 6c 65 64 5f 61 63 63 65 73 73 69 62 69 6c 69 74 79 5f 73 65 72 76 69 63 65 73 } //01 00  enabled_accessibility_services
		$a_00_4 = {69 73 5f 64 6f 7a 65 6d 6f 64 65 } //01 00  is_dozemode
		$a_00_5 = {6f 6e 49 6e 63 6f 6d 69 6e 67 43 61 6c 6c 41 6e 73 77 65 72 65 64 } //01 00  onIncomingCallAnswered
		$a_00_6 = {6f 6e 4f 75 74 67 6f 69 6e 67 43 61 6c 6c 53 74 61 72 74 65 64 } //00 00  onOutgoingCallStarted
	condition:
		any of ($a_*)
 
}