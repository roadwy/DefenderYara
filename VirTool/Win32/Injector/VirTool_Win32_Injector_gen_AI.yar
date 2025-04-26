
rule VirTool_Win32_Injector_gen_AI{
	meta:
		description = "VirTool:Win32/Injector.gen!AI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 08 89 4d ?? 8d 95 ?? ?? ff ff 52 6a 00 55 9c 51 87 e9 b9 de fa 00 00 81 f9 ee ff c0 00 74 fa } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}