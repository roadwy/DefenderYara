
rule VirTool_Win32_DelfInject_gen_DI{
	meta:
		description = "VirTool:Win32/DelfInject.gen!DI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7f 04 00 00 75 e2 6a 40 68 00 30 00 00 68 7f 04 00 00 6a 00 e8 90 09 18 00 a1 ?? ?? ?? ?? 80 b0 ?? ?? ?? ?? f9 ff 05 ?? ?? ?? ?? 81 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}