
rule VirTool_Win32_DelfInject_gen_AN{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 43 34 8d 45 e8 50 56 8b 45 10 50 8b 45 e4 50 8b 45 f8 50 e8 ?? ?? ?? ff 85 c0 74 47 c7 85 ?? ff ff ff 07 00 01 00 } //1
		$a_03_1 = {89 14 24 8b e8 33 db 68 ?? ?? ?? ?? e8 ?? ?? ?? ff 8b f8 85 ff 74 23 68 ?? ?? ?? ?? 57 e8 ?? ?? ?? ff 8b f0 85 f6 74 0c 8b 04 24 50 55 ff d6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}