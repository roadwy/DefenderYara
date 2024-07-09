
rule VirTool_Win32_CeeInject_gen_HD{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 b9 03 00 00 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8a 8c 8d ?? ?? ?? ?? 30 0c 1a 99 6a 03 59 f7 f9 6a 05 59 99 f7 f9 } //1
		$a_03_1 = {8b 8d 4c fe ff ff 03 8d 58 fe ff ff 89 8d ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}