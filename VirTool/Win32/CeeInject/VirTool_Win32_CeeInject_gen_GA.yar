
rule VirTool_Win32_CeeInject_gen_GA{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 50 8b 55 08 52 ff 15 } //1
		$a_02_1 = {6a 00 8b 95 ?? ?? ff ff 8b 42 ?? 50 8b 4d ?? 51 8b 95 ?? ?? ff ff 8b 42 ?? 50 8b 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? c7 85 ?? ?? ff ff 00 00 00 00 eb } //1
		$a_02_2 = {6a 00 6a 04 8b 8d ?? ?? ff ff 83 c1 34 51 8b 95 ?? ?? ff ff 83 c2 08 52 8b 85 ?? ?? ff ff 50 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}