
rule VirTool_Win32_CeeInject_gen_KF{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4e 50 8b d1 c1 e9 02 8b f3 8b fd f3 a5 8b ca 83 e1 03 55 f3 a4 e8 c2 fe ff ff 8b 44 24 1c 8d 48 d8 51 ba 10 47 40 00 50 2b d3 55 03 d5 ff d2 83 c4 10 e9 18 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}