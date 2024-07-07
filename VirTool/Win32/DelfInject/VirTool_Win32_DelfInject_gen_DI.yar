
rule VirTool_Win32_DelfInject_gen_DI{
	meta:
		description = "VirTool:Win32/DelfInject.gen!DI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7f 04 00 00 75 e2 6a 40 68 00 30 00 00 68 7f 04 00 00 6a 00 e8 90 09 18 00 a1 90 01 04 80 b0 90 01 04 f9 ff 05 90 01 04 81 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}