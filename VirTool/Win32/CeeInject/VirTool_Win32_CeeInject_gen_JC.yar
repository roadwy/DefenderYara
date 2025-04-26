
rule VirTool_Win32_CeeInject_gen_JC{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 7d f8 03 0f 8d 9a 00 00 00 c7 45 f4 00 00 00 00 eb 09 8b 55 f4 83 c2 01 89 55 f4 83 7d f4 06 7d 90 09 38 00 [0-18] 0f be 88 ?? ?? 41 00 8b 55 fc 83 c2 01 90 04 01 02 81 83 [0-05] 2b ca 8b 45 fc 88 88 } //2
		$a_03_1 = {81 7d fc da 25 00 00 0f 84 ?? 00 00 00 8b 45 fc 0f be 88 ?? ?? ?? ?? 8b 55 fc 83 c2 01 90 04 01 02 81 83 [0-05] 2b ca 8b 45 fc 88 88 ?? ?? ?? ?? c7 45 f8 ?? ?? ?? ?? eb 18 8b 4d f8 0f be 11 } //2
		$a_01_2 = {00 68 6f 6d 65 77 6f 72 6b 00 } //1 栀浯睥牯k
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=2
 
}