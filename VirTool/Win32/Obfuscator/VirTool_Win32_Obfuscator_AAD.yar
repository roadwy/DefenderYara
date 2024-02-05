
rule VirTool_Win32_Obfuscator_AAD{
	meta:
		description = "VirTool:Win32/Obfuscator.AAD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec 80 12 00 00 56 57 53 50 81 ec 00 10 00 00 6a ff 6a 00 67 8d 06 04 00 6a 00 f9 50 83 c8 ff 50 25 f8 05 00 00 50 54 ff 15 90 01 04 8b d4 8d 52 30 8b fa 83 c7 1c f8 66 26 11 44 24 68 6a 01 c7 07 90 01 01 00 00 00 89 7a 04 c7 02 00 00 00 00 52 57 85 c0 74 0d 3d 50 02 00 00 77 06 36 be 90 01 04 3e f3 ff 16 90 00 } //01 00 
		$a_00_1 = {f7 14 24 90 90 90 9c 80 24 24 fe 90 90 90 90 9d 26 0f 83 } //01 00 
		$a_00_2 = {31 04 24 87 d2 90 90 90 90 f2 f3 36 26 e9 } //01 00 
		$a_03_3 = {b9 65 00 00 00 50 8d 05 90 01 04 87 04 24 c3 90 00 } //00 00 
		$a_00_4 = {5d 04 00 00 01 b1 } //02 80 
	condition:
		any of ($a_*)
 
}