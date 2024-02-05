
rule TrojanDropper_Win32_Twores{
	meta:
		description = "TrojanDropper:Win32/Twores,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0f 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 6e 75 6d 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 41 } //01 00 
		$a_00_1 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //01 00 
		$a_00_2 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //04 00 
		$a_00_3 = {00 4f 50 45 4e 00 } //04 00 
		$a_01_4 = {6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 } //0a 00 
		$a_03_5 = {8a 44 10 ff 8a 54 1d ff 32 c2 88 07 47 43 8b c5 e8 90 01 04 3b d8 7e 05 bb 01 00 00 00 ff 44 24 90 01 01 4e 75 90 00 } //0a 00 
		$a_03_6 = {83 e8 01 72 0a 74 1b 48 74 2b 48 74 3b eb 4a 68 04 01 00 00 8d 85 90 01 02 ff ff 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}