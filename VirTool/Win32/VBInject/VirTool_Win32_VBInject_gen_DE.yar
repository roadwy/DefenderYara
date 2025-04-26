
rule VirTool_Win32_VBInject_gen_DE{
	meta:
		description = "VirTool:Win32/VBInject.gen!DE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {f5 04 00 00 00 f5 58 59 59 59 } //1
		$a_03_1 = {f4 58 fc 0d [0-11] f4 59 fc 0d [0-11] f4 59 fc 0d [0-11] f4 59 fc 0d } //1
		$a_03_2 = {f5 40 00 00 00 f5 00 30 00 00 6c ?? ?? 6c ?? ?? 6c ?? ?? 0a } //2
		$a_03_3 = {f5 07 00 01 00 71 ?? ?? f5 00 00 00 00 f5 00 00 00 00 04 ?? ?? fe 8e 01 00 00 00 10 00 80 08 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=5
 
}