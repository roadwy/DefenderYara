
rule TrojanDropper_Win32_Daonol_E{
	meta:
		description = "TrojanDropper:Win32/Daonol.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 79 73 61 75 64 69 6f 2e 73 79 73 00 } //01 00 
		$a_01_1 = {61 75 78 00 } //01 00  畡x
		$a_01_2 = {3a 5c 5f 2e 65 } //02 00  :\_.e
		$a_01_3 = {80 f1 d5 88 4c 02 ff 4a 75 f2 c3 } //02 00 
		$a_03_4 = {c7 44 24 04 2e 2e 5c 00 54 68 3f 00 0f 00 6a 00 b8 90 01 04 ba 37 00 00 00 90 00 } //02 00 
		$a_03_5 = {4e 83 fe 00 7c 16 b8 19 00 00 00 e8 90 01 02 ff ff 83 c0 61 88 03 43 4e 83 fe ff 75 ea c6 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}