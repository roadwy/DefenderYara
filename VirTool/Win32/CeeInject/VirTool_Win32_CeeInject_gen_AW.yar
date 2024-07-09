
rule VirTool_Win32_CeeInject_gen_AW{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 14 08 8b c6 32 d3 83 e0 ?? b9 08 00 00 00 8a da 2b c8 d2 e3 8a c8 d2 ea 0a da 88 1c 3e 46 3b f5 72 d1 } //2
		$a_03_1 = {8b 48 34 03 48 28 8d 85 ?? ?? ff ff } //1
		$a_01_2 = {83 45 0c 28 43 0f b7 41 06 3b d8 7c bc } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}