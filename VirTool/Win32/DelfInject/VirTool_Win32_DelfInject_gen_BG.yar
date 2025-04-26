
rule VirTool_Win32_DelfInject_gen_BG{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 47 28 03 45 f0 89 85 7c ff ff ff 8d 85 cc fe ff ff } //1
		$a_03_1 = {32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 0f b6 54 1a ff 80 e2 f0 0f b6 4d f3 02 d1 88 54 18 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}