
rule VirTool_Win32_DelfInject_gen_CP{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 40 28 03 45 90 01 01 8b 55 90 01 01 89 82 b0 00 00 00 90 00 } //01 00 
		$a_03_1 = {6a 04 8d 45 90 01 01 50 8b 45 90 01 01 8b 80 a4 00 00 00 83 c0 08 90 00 } //01 00 
		$a_01_2 = {c7 00 07 00 01 00 } //01 00 
		$a_03_3 = {6a 40 68 00 30 00 00 8b 45 90 01 01 8b 40 50 50 8b 45 90 01 01 8b 40 34 90 00 } //f6 ff 
		$a_01_4 = {69 70 65 72 66 20 76 2e } //f6 ff 
		$a_01_5 = {5c 67 64 6d 5c 64 65 6c 70 68 69 5c 6d 61 74 68 5c } //01 00 
	condition:
		any of ($a_*)
 
}