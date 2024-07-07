
rule VirTool_Win32_Obfuscator_UW{
	meta:
		description = "VirTool:Win32/Obfuscator.UW,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 03 00 00 "
		
	strings :
		$a_02_0 = {d1 ea f7 d0 40 29 04 55 90 01 02 00 00 b8 00 00 00 00 f8 74 90 01 01 68 90 01 04 58 03 c0 8d 04 01 f8 ff 20 90 00 } //5
		$a_02_1 = {8b 04 24 57 bf 90 01 02 40 00 87 3c 24 c3 90 00 } //1
		$a_02_2 = {f8 f2 fc eb 00 0f 83 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=6
 
}