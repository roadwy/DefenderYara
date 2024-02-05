
rule VirTool_Win32_DelfInject_gen_AL{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a ff ff 15 90 01 04 85 c0 74 08 6a 00 ff 15 90 00 } //02 00 
		$a_01_1 = {66 b9 ff ff eb 06 66 b8 00 4c cd 21 e2 f6 } //02 00 
		$a_03_2 = {83 c0 01 89 45 90 01 01 33 c9 8a 0d 90 01 04 85 c9 74 eb 81 7d 90 01 01 00 e1 f5 05 7d 08 6a 00 ff 15 90 00 } //01 00 
		$a_01_3 = {81 e2 ff 00 00 00 81 fa e9 00 00 00 75 08 6a 00 ff 15 } //01 00 
	condition:
		any of ($a_*)
 
}