
rule TrojanSpy_Win32_Bancos_ACU{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 0f b7 54 58 fe 8b c3 3b f0 7d 02 8b c6 8b 4d f8 0f b7 44 41 fe 33 d0 8b c2 66 89 45 ee 8d 45 e4 0f b7 55 ee } //01 00 
		$a_00_1 = {6f 00 70 00 65 00 6e 00 00 00 00 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 37 00 78 00 65 00 5c 00 77 00 69 00 6e 00 37 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}