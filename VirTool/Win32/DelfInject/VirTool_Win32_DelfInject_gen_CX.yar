
rule VirTool_Win32_DelfInject_gen_CX{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 00 02 00 01 00 } //1
		$a_01_1 = {8b 80 a4 00 00 00 83 c0 08 } //1
		$a_03_2 = {03 42 28 8b 15 ?? ?? ?? ?? 8b 12 89 82 b0 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}