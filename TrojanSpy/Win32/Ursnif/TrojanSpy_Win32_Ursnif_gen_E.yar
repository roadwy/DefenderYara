
rule TrojanSpy_Win32_Ursnif_gen_E{
	meta:
		description = "TrojanSpy:Win32/Ursnif.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 85 dc fe ff ff 51 e8 90 01 02 ff ff 83 f8 ff 74 16 6a 00 68 90 01 04 e8 90 01 02 ff ff 50 ff 15 90 00 } //02 00 
		$a_03_1 = {68 01 00 00 98 56 c7 44 24 2c 00 00 00 00 c7 44 24 30 01 00 00 00 ff 15 90 01 04 83 f8 ff 75 10 90 00 } //01 00 
		$a_03_2 = {7e 26 53 8b 5c 24 14 8d a4 24 00 00 00 00 33 c9 8a 0c 1e 8d 44 24 0c 50 51 e8 90 01 04 46 3b f7 7c eb 90 00 } //01 00 
		$a_01_3 = {63 68 61 6e 67 65 72 65 73 65 72 76 00 } //01 00 
		$a_01_4 = {6f 70 74 5f 63 65 72 74 73 00 } //01 00  灯彴散瑲s
		$a_01_5 = {33 70 6f 73 74 76 61 6c 75 65 } //01 00  3postvalue
		$a_01_6 = {57 45 42 20 46 4f 55 4e 44 45 44 00 } //01 00  䕗⁂但乕䕄D
		$a_01_7 = {6f 70 74 69 6f 6e 73 2e 63 67 69 } //00 00  options.cgi
	condition:
		any of ($a_*)
 
}