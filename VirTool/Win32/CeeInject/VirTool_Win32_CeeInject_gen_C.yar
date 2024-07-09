
rule VirTool_Win32_CeeInject_gen_C{
	meta:
		description = "VirTool:Win32/CeeInject.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 81 c9 00 ff ff ff 41 8a 4c 0c 14 32 0c 2f 88 0f 8b 8c 24 20 01 00 00 40 3b c1 7c 9e 8b 44 24 10 } //1
		$a_03_1 = {83 c4 0c 50 6a 09 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 50 ff d7 50 ff d5 8b 4c 24 2c 8b 54 24 28 51 8b 4c 24 24 52 51 53 56 6a 02 a3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}