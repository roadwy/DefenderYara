
rule VirTool_Win32_Injector_gen_DT{
	meta:
		description = "VirTool:Win32/Injector.gen!DT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 ff ff ff 7f 31 c9 39 c8 75 0a 74 0e bb 00 00 00 00 89 1b c3 48 39 c8 eb ed c3 b9 ff ff ff 7f 90 e2 fd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}