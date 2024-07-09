
rule VirTool_Win32_CeeInject_gen_GV{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 8b 45 ?? 8b 48 50 51 8b 55 ?? 8b 42 34 } //1
		$a_01_1 = {c7 45 fc 07 00 01 00 } //1
		$a_03_2 = {0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 8b 95 ?? ff ff ff 83 c2 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}