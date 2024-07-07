
rule VirTool_Win32_VBInject_gen_JF{
	meta:
		description = "VirTool:Win32/VBInject.gen!JF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 70 fe 6c 64 fe aa 30 9c fd } //1
		$a_00_1 = {f5 58 59 59 59 } //1
		$a_03_2 = {01 00 71 ec fc 90 09 03 00 f5 07 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}