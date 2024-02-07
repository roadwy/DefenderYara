
rule TrojanSpy_Win32_Small_DI{
	meta:
		description = "TrojanSpy:Win32/Small.DI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 20 57 65 62 4d 6f 6e 65 79 00 } //01 00  敓摮圠扥潍敮y
		$a_00_1 = {6d 61 6d 62 6f 74 73 2f 77 2f 43 66 67 2e 74 78 74 00 } //01 00 
		$a_00_2 = {43 6f 64 65 64 5f 62 79 5f 4e 6f 63 74 61 6d 62 75 6c 61 61 72 00 } //01 00  潃敤彤祢也捯慴扭汵慡r
		$a_00_3 = {6f 77 3d 6f 70 74 69 6f 6e 73 00 00 77 6d 6b 3a 70 61 79 74 6f 3f 50 75 72 73 65 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}