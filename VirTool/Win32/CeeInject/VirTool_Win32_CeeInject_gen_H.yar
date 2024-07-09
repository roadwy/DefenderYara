
rule VirTool_Win32_CeeInject_gen_H{
	meta:
		description = "VirTool:Win32/CeeInject.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 40 00 00 00 b8 00 30 00 00 89 4c 24 10 89 44 24 0c 8b 55 ?? 89 54 24 08 8b 5e 34 89 5c 24 04 8b 8d ?? ?? ff ff 89 0c 24 } //1
		$a_03_1 = {29 d0 0f b6 84 28 ?? ?? ff ff 32 04 0b 88 04 33 43 39 5d 10 0f 8e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}