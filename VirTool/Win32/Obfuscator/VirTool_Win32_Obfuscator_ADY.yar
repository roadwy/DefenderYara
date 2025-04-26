
rule VirTool_Win32_Obfuscator_ADY{
	meta:
		description = "VirTool:Win32/Obfuscator.ADY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 fa 07 75 02 eb 06 42 e9 } //2
		$a_01_1 = {83 c4 14 83 c8 ff eb 5f e8 24 02 00 00 6a 20 5b 03 c3 50 6a 01 e8 2f 03 00 00 59 59 89 75 fc e8 0d 02 00 00 03 c3 } //1
		$a_01_2 = {e8 c3 06 00 00 83 c4 04 85 c0 74 0f 8b 55 08 6a 01 52 ff 15 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}