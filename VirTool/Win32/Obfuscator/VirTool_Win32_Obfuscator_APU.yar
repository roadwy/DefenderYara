
rule VirTool_Win32_Obfuscator_APU{
	meta:
		description = "VirTool:Win32/Obfuscator.APU,SIGNATURE_TYPE_PEHSTR,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 9d 28 ff ff ff 8b 1b 53 5e 31 fe 83 c7 01 81 fe 66 b8 00 00 75 f1 } //1
		$a_01_1 = {8b b5 34 ff ff ff 89 f7 8b 85 44 ff ff ff bb 04 00 00 00 f6 f3 89 c1 8b 9d 54 ff ff ff ad 31 d8 ab e2 fa ff a5 34 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}