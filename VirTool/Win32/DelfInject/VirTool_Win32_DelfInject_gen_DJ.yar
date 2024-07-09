
rule VirTool_Win32_DelfInject_gen_DJ{
	meta:
		description = "VirTool:Win32/DelfInject.gen!DJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 e8 03 00 00 90 09 1d 00 07 00 01 00 8d 85 ?? ?? ff ff 50 8b 45 ?? 50 ff 15 ?? ?? ?? 00 84 c0 0f 84 ?? 01 00 00 } //1
		$a_03_1 = {8b 40 34 50 8b 45 d4 50 ff 15 ?? ?? ?? 00 85 c0 75 ?? b8 f4 01 00 00 e8 ?? ?? ff ff 6a 40 68 00 30 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}