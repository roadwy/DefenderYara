
rule VirTool_Win32_CeeInject_gen_JK{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5e 83 ee 6e 8b 06 8b f0 c1 e6 10 66 33 f6 81 ee ?? ?? ?? ?? 64 8b 01 8b 58 04 c7 40 04 ?? ?? ?? ?? b0 4c 3a 06 74 03 83 ee 08 2a 06 74 03 83 ee 08 8d 86 a8 00 00 00 b1 38 2a 08 74 06 b5 1c 2a 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}