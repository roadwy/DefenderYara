
rule VirTool_Win32_DelfInject_gen_BH{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 34 9b 8b 45 90 01 01 8b 44 f0 10 50 8b 45 90 01 01 8b 44 f0 14 03 c7 50 8b 45 90 01 01 8b 44 f0 0c 03 45 90 00 } //01 00 
		$a_03_1 = {25 ff 00 00 00 89 84 9d 90 01 02 ff ff 8b 84 b5 90 1b 00 ff ff 03 84 9d 90 1b 00 ff ff 25 ff 00 00 00 8a 84 85 90 1b 00 ff ff 8b 55 90 01 01 30 04 3a 47 ff 4d 90 01 01 75 90 00 } //01 00 
		$a_03_2 = {8b 47 3c 03 c7 89 45 90 01 01 8b 45 90 1b 00 8b 90 01 01 50 6a 04 68 00 30 00 00 90 01 01 8b 45 90 1b 00 e8 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}