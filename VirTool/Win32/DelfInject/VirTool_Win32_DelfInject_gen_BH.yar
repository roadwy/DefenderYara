
rule VirTool_Win32_DelfInject_gen_BH{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 34 9b 8b 45 ?? 8b 44 f0 10 50 8b 45 ?? 8b 44 f0 14 03 c7 50 8b 45 ?? 8b 44 f0 0c 03 45 } //1
		$a_03_1 = {25 ff 00 00 00 89 84 9d ?? ?? ff ff 8b 84 b5 90 1b 00 ff ff 03 84 9d 90 1b 00 ff ff 25 ff 00 00 00 8a 84 85 90 1b 00 ff ff 8b 55 ?? 30 04 3a 47 ff 4d ?? 75 } //1
		$a_03_2 = {8b 47 3c 03 c7 89 45 ?? 8b 45 90 1b 00 8b ?? 50 6a 04 68 00 30 00 00 ?? 8b 45 90 1b 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}