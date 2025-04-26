
rule VirTool_Win32_Injector_gen_W{
	meta:
		description = "VirTool:Win32/Injector.gen!W,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 0c 37 40 83 f8 0b 72 f1 8a 04 37 56 f6 d0 88 04 37 47 } //1
		$a_01_1 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed } //1
		$a_03_2 = {eb 0b 8b 4f 10 03 c8 89 8d ?? ?? ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}