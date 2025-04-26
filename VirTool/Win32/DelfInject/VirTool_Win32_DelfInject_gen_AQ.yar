
rule VirTool_Win32_DelfInject_gen_AQ{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 28 6d 01 00 e8 ?? ?? ff ff 84 c0 0f 84 ca 17 00 00 83 3d ac 8b 01 00 00 0f 84 88 17 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}