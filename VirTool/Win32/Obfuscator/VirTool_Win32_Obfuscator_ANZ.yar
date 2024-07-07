
rule VirTool_Win32_Obfuscator_ANZ{
	meta:
		description = "VirTool:Win32/Obfuscator.ANZ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 ec 5d e8 fb ff ff ff } //1
		$a_03_1 = {66 81 fd 00 fd 90 03 01 01 72 0f 90 00 } //1
		$a_03_2 = {66 81 fd 00 fe 0f 82 90 01 04 8b 90 01 01 81 90 01 01 00 08 00 00 76 08 8d 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}