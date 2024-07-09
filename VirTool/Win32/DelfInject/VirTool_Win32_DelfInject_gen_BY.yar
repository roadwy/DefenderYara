
rule VirTool_Win32_DelfInject_gen_BY{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 03 8d 04 80 99 03 04 24 13 54 24 04 83 c4 08 8b 55 ?? 03 d0 8d 85 ?? ?? ff ff b9 28 00 00 00 } //1
		$a_03_1 = {b9 00 04 00 00 8d 85 ?? ?? ff ff e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c7 8b 55 f8 e8 ?? ?? ?? ?? 2b 75 f4 81 fe 00 (04|90 90) 00 00 7f bb } //1
		$a_03_2 = {b9 f8 00 00 00 e8 ?? ?? ?? ?? 81 bd ?? ?? ff ff 50 45 00 00 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}