
rule VirTool_Win32_DelfInject_gen_DL{
	meta:
		description = "VirTool:Win32/DelfInject.gen!DL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b9 07 00 01 00 89 08 } //1
		$a_03_1 = {ff 53 60 6a 00 ff 75 90 01 01 ff 93 88 00 00 00 90 00 } //1
		$a_01_2 = {68 d2 c7 f0 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}