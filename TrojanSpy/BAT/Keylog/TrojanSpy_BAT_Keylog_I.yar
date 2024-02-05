
rule TrojanSpy_BAT_Keylog_I{
	meta:
		description = "TrojanSpy:BAT/Keylog.I,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 48 4f 4f 4b 45 00 } //01 00 
		$a_01_1 = {00 54 68 79 53 65 6e 64 00 } //01 00 
		$a_01_2 = {00 44 65 63 72 79 70 74 44 61 74 61 00 } //0f 00 
		$a_01_3 = {00 4b 45 43 41 42 41 00 } //00 00 
	condition:
		any of ($a_*)
 
}