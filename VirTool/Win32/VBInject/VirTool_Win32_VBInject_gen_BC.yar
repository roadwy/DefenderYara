
rule VirTool_Win32_VBInject_gen_BC{
	meta:
		description = "VirTool:Win32/VBInject.gen!BC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 70 00 00 00 8b 85 ?? (fa|fb) ff ff 03 85 ?? fd ff ff 89 85 ?? 90 03 01 01 fb fc ff ff c7 45 fc 71 00 00 00 } //1
		$a_03_1 = {c7 45 fc 10 00 00 00 81 bd ?? (fd|fc) ff ff 50 45 00 00 74 05 e9 } //1
		$a_03_2 = {2b 51 14 8b 40 0c 8a 04 10 32 05 ?? ?? ?? ?? 8b 4d 08 8b 09 8b 55 08 8b 12 8b 35 ?? ?? ?? ?? 2b 72 14 8b 49 0c 88 04 31 c7 45 fc 23 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}