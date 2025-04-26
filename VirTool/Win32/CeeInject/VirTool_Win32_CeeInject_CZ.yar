
rule VirTool_Win32_CeeInject_CZ{
	meta:
		description = "VirTool:Win32/CeeInject.CZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {e9 11 00 00 00 8b 4d c4 3b c1 0f 85 13 00 00 00 50 } //1
		$a_01_1 = {46 89 7d fc 83 fe 17 } //1
		$a_01_2 = {3d 68 0d 00 00 0f 84 0d 00 00 00 } //1
		$a_01_3 = {83 f9 28 0f 82 95 ff ff ff 5f 5e 5b c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}