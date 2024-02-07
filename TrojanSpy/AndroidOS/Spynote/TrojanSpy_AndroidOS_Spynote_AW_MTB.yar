
rule TrojanSpy_AndroidOS_Spynote_AW_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.AW!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 43 6f 6e 66 69 67 2f 73 79 73 2f 61 70 70 73 2f 6c 6f 67 2f 6c 6f 67 2d } //01 00  /Config/sys/apps/log/log-
		$a_00_1 = {65 6e 61 62 6c 65 64 5f 61 63 63 65 73 73 69 62 69 6c 69 74 79 5f 73 65 72 76 69 63 65 73 } //01 00  enabled_accessibility_services
		$a_00_2 = {67 65 74 4c 61 75 6e 63 68 49 6e 74 65 6e 74 46 6f 72 50 61 63 6b 61 67 65 } //01 00  getLaunchIntentForPackage
		$a_00_3 = {70 68 6f 6e 69 78 65 66 66 65 63 74 } //00 00  phonixeffect
	condition:
		any of ($a_*)
 
}