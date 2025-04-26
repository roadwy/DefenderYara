
rule VirTool_Win32_CeeInject_gen_CN{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 fe 0f b6 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8b 54 24 ?? 8d 84 ?? ?? ?? ?? ?? 99 f7 fe 83 c1 05 0f b6 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 83 f9 } //1
		$a_02_1 = {8a 44 b4 10 8b 54 bc 10 89 54 b4 10 0f b6 c0 89 44 bc 10 33 d2 8d 41 ff f7 f3 0f b6 92 ?? ?? ?? ?? 03 d7 03 54 b4 14 8b fa 81 e7 ff 00 00 80 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}