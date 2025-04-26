
rule VirTool_Win32_CeeInject_gen_GQ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 14 31 32 d0 88 14 31 41 3b cf 7e e4 } //1
		$a_03_1 = {81 cb 00 ff ff ff 43 8a 9c 9d ?? ?? ff ff 8b 7d ?? 30 1c 02 42 3b d7 72 } //1
		$a_01_2 = {c6 00 e9 8b 16 42 8b c2 89 16 2b d8 8d 54 3b fc } //1
		$a_03_3 = {66 8b 41 06 83 c3 28 3b f8 7c af 90 18 a1 ?? ?? ?? ?? 6a 00 8b 50 3c 03 d3 8d 84 32 f8 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}