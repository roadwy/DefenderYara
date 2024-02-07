
rule MonitoringTool_MSIL_CyborgLog{
	meta:
		description = "MonitoringTool:MSIL/CyborgLog,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 79 00 62 00 6f 00 72 00 67 00 20 00 76 00 32 00 2e 00 30 00 20 00 3a 00 2d 00 3a 00 2d 00 3a 00 } //01 00  Cyborg v2.0 :-:-:
		$a_01_1 = {61 00 74 00 61 00 44 00 64 00 6e 00 65 00 53 00 } //01 00  ataDdneS
		$a_01_2 = {4b 65 79 62 6f 61 72 64 48 6f 6f 6b } //01 00  KeyboardHook
		$a_01_3 = {5b 00 57 00 69 00 6e 00 64 00 6f 00 77 00 3a 00 5d 00 } //00 00  [Window:]
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}