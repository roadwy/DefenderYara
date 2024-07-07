
rule VirTool_Win32_CeeInject_gen_W{
	meta:
		description = "VirTool:Win32/CeeInject.gen!W,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {3b 45 e4 75 0e 8b 47 10 03 47 1c 89 85 c8 fd ff ff eb 0b } //2
		$a_01_1 = {b8 68 58 4d 56 } //1
		$a_01_2 = {68 58 4d 56 0f 94 c0 } //1
		$a_01_3 = {8a 84 95 b4 fb ff ff 30 03 ff 45 14 8b 45 14 3b 45 10 72 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}