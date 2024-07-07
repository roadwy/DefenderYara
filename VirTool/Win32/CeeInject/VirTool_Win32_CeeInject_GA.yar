
rule VirTool_Win32_CeeInject_GA{
	meta:
		description = "VirTool:Win32/CeeInject.GA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_09_0 = {8b 45 f0 81 78 60 45 76 38 12 75 12 } //1
		$a_09_1 = {c6 85 7f ff ff ff 6d c6 45 80 70 c6 45 81 72 c6 45 82 65 c6 45 83 73 } //1
		$a_09_2 = {c6 45 90 74 c6 45 91 65 c6 45 92 46 c6 45 93 69 } //1
		$a_09_3 = {c6 45 f8 63 c6 45 f9 3a c6 45 fa 5c c6 45 fb 30 c6 45 fc 00 8d 45 f8 50 ff 55 08 } //1
		$a_09_4 = {81 ef 5d 00 00 00 b9 20 00 00 00 b8 5f c3 5f c3 f3 ab cc } //1
	condition:
		((#a_09_0  & 1)*1+(#a_09_1  & 1)*1+(#a_09_2  & 1)*1+(#a_09_3  & 1)*1+(#a_09_4  & 1)*1) >=5
 
}