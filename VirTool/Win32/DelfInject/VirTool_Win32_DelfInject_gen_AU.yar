
rule VirTool_Win32_DelfInject_gen_AU{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d0 85 c0 74 31 8b 45 ?? 8b 50 28 8b 45 ?? e8 ?? ?? ff ff 89 85 ?? ff ff ff } //1
		$a_01_1 = {32 c1 8b 4d f8 8b 7d e4 0f b6 4c 39 ff 03 c9 c1 e9 02 32 c1 32 d0 88 55 ef } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}