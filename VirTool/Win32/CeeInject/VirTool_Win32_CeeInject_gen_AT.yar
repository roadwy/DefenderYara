
rule VirTool_Win32_CeeInject_gen_AT{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 30 00 00 8b 56 50 52 8b 46 34 50 } //1
		$a_03_1 = {81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8b 54 8c ?? 8a 04 37 32 d0 8b 44 24 ?? 88 16 46 48 89 44 24 ?? 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}