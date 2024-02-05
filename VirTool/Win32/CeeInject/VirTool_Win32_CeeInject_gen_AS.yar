
rule VirTool_Win32_CeeInject_gen_AS{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AS,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {f7 f1 40 0f af c1 01 44 24 90 01 01 ff 44 24 90 01 01 0f b7 90 01 01 06 83 44 24 90 01 01 28 39 44 24 90 01 01 0f 8c 90 00 } //01 00 
		$a_01_1 = {b8 68 58 4d 56 } //01 00 
		$a_01_2 = {bb e8 03 00 00 0f b6 04 06 03 45 f8 } //01 00 
		$a_01_3 = {83 45 f8 09 46 ff 45 fc 88 18 8b 45 fc 3b 45 10 0f 82 } //01 00 
		$a_01_4 = {54 68 65 20 57 69 72 65 73 68 61 72 6b 20 4e 65 74 77 6f 72 6b 20 41 6e 61 6c 79 7a 65 72 00 } //02 00 
		$a_03_5 = {6a 40 68 00 30 00 00 90 02 0a ff 90 01 01 50 ff 90 01 01 34 ff 74 24 90 01 01 ff 15 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}