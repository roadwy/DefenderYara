
rule TrojanSpy_Win32_Gauss_plugin_G{
	meta:
		description = "TrojanSpy:Win32/Gauss.plugin!G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 00 49 00 73 00 76 00 70 00 34 00 30 00 30 00 33 00 6c 00 74 00 72 00 45 00 76 00 65 00 6e 00 74 00 00 00 } //01 00 
		$a_03_1 = {89 7d fc 50 8d 45 fc 68 86 0b 00 00 50 6a 65 57 89 7d 90 01 01 89 7d 90 01 01 89 7d 90 01 01 e8 07 0e 00 00 3b c7 74 0b 3d ea 00 00 00 0f 85 90 01 04 6a 66 e8 90 01 04 39 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Gauss_plugin_G_2{
	meta:
		description = "TrojanSpy:Win32/Gauss.plugin!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 5d 08 8d 43 05 35 90 01 04 83 3d 90 01 04 00 56 57 c7 45 fc 01 00 00 00 89 45 08 75 90 01 01 6a 04 5e 56 90 00 } //01 00 
		$a_02_1 = {c7 45 fc 00 28 00 00 ff 15 90 01 04 8b d8 85 db 0f 84 90 01 04 57 6a 70 e8 90 01 04 83 65 f4 00 83 65 f8 00 8b 3d 90 01 04 59 83 7d f4 14 90 00 } //01 00 
		$a_00_2 = {74 00 61 00 72 00 67 00 65 00 74 00 2e 00 6c 00 6e 00 6b 00 } //00 00  target.lnk
	condition:
		any of ($a_*)
 
}