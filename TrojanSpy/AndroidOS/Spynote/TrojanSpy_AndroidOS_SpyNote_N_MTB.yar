
rule TrojanSpy_AndroidOS_SpyNote_N_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyNote.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 6e 61 62 6c 65 64 5f 61 63 63 65 73 73 69 62 69 6c 69 74 79 5f 73 65 72 76 69 63 65 73 } //01 00  enabled_accessibility_services
		$a_01_1 = {2e 63 6f 73 74 6d } //01 00  .costm
		$a_01_2 = {2e 4d 61 69 6e 41 63 74 69 76 65 } //01 00  .MainActive
		$a_01_3 = {2f 43 6f 6e 66 69 67 2f 73 79 73 2f 61 70 70 73 2f 6c 6f 67 2f 6c 6f 67 2d } //00 00  /Config/sys/apps/log/log-
	condition:
		any of ($a_*)
 
}