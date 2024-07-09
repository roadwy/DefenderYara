
rule VirTool_Win32_CeeInject_gen_EU{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 11 81 e2 00 00 00 80 74 ?? 8b 45 ?? 8b 08 81 e1 ff ff 00 00 51 8b 55 ?? 52 ff 15 ?? ?? ?? ?? 8b 4d ?? 89 01 } //1
		$a_03_1 = {03 48 3c 89 4d ?? 8b 55 ?? 8b 42 50 89 45 ?? 6a 00 8b 4d ?? 51 8b 55 ?? 52 8b 45 08 50 8b 4d ?? 51 ff 15 ?? ?? ?? ?? 8b 55 ?? 8b 45 08 03 42 28 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}