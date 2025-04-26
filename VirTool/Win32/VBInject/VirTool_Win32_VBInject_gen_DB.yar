
rule VirTool_Win32_VBInject_gen_DB{
	meta:
		description = "VirTool:Win32/VBInject.gen!DB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {f5 04 00 00 00 f5 58 59 59 59 } //1
		$a_03_1 = {f4 58 fc 0d [0-11] f4 59 fc 0d [0-11] f4 59 fc 0d [0-11] f4 59 fc 0d } //1
		$a_03_2 = {f5 07 00 01 00 71 ?? ?? f5 00 00 00 00 f5 07 00 00 00 04 ?? ?? ?? 8e 01 00 00 00 10 00 80 08 28 ?? ?? 6b 00 f5 00 00 00 00 6c ?? ?? 52 28 ?? ?? 65 00 f5 01 00 00 00 6c ?? ?? 52 28 ?? ?? 72 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}