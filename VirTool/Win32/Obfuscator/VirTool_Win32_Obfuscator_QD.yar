
rule VirTool_Win32_Obfuscator_QD{
	meta:
		description = "VirTool:Win32/Obfuscator.QD,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 60 48 46 51 4d c7 45 64 46 4f 10 11 c7 45 68 0d 47 4f 4f } //01 00 
		$a_01_1 = {c7 45 18 60 51 46 42 c7 45 1c 57 46 73 51 c7 45 20 4c 40 46 50 66 c7 45 24 50 62 } //01 00 
		$a_01_2 = {c7 45 b8 74 51 4a 57 c7 45 bc 46 73 51 4c c7 45 c0 40 46 50 50 c7 45 c4 6e 46 4e 4c 66 c7 45 c8 51 5a } //01 00 
		$a_01_3 = {c7 45 cc 6f 4c 42 47 c7 45 d0 71 46 50 4c c7 45 d4 56 51 40 46 } //01 00 
		$a_01_4 = {0d 00 ff ff ff 40 8a 44 85 90 30 04 1e 43 3b } //00 00 
	condition:
		any of ($a_*)
 
}