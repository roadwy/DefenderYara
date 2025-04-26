
rule VirTool_Win32_CeeInject_gen_KE{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4e 50 8b c1 c1 e9 02 8b f3 8b fd f3 a5 8b c8 83 e1 03 55 f3 a4 e8 54 fe ff ff 8b 8c 24 68 01 00 00 8b 54 24 20 51 b8 10 21 40 00 52 2b c3 55 03 c5 ff d0 83 c4 10 e9 70 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}