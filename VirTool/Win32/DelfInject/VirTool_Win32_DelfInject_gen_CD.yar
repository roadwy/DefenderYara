
rule VirTool_Win32_DelfInject_gen_CD{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 03 8d 04 80 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 d0 8b c6 b9 28 00 00 00 e8 ?? ?? ff ff } //1
		$a_01_1 = {83 c0 02 89 45 f0 6a 04 68 00 30 00 00 ff 75 fc ff 75 f8 ff 75 f4 8b 45 f0 83 e8 02 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}