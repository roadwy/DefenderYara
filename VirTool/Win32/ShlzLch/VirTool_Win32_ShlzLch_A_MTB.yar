
rule VirTool_Win32_ShlzLch_A_MTB{
	meta:
		description = "VirTool:Win32/ShlzLch.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 20 00 00 68 00 00 10 00 57 ff 15 90 01 04 3b c7 89 46 0c 90 00 } //01 00 
		$a_03_1 = {56 57 33 ff 3b c1 90 01 02 8d 90 01 03 c1 e0 90 01 01 50 ff 35 90 01 04 57 ff 35 90 01 04 ff 15 90 01 04 3b c7 90 01 02 83 90 01 05 10 a3 90 00 } //01 00 
		$a_03_2 = {50 ff 74 24 18 56 e8 90 01 04 56 57 8b d8 e8 90 01 04 83 c4 90 01 01 8b c3 5f 5e 5b c3 90 00 } //01 00 
		$a_03_3 = {c7 45 f8 00 00 00 00 8d 90 01 02 52 8d 90 01 05 50 e8 90 01 04 83 c4 90 01 01 85 c0 90 01 02 68 90 01 04 e8 90 01 04 83 c4 90 01 01 b8 01 00 00 00 90 00 } //01 00 
		$a_03_4 = {8b 45 f8 89 45 fc 8b 4d f8 81 c1 00 00 01 00 51 68 90 01 04 e8 90 01 04 83 c4 08 ff 90 01 02 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}