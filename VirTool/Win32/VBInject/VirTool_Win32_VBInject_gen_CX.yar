
rule VirTool_Win32_VBInject_gen_CX{
	meta:
		description = "VirTool:Win32/VBInject.gen!CX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 59 00 00 00 90 02 08 b9 58 00 00 00 90 02 08 88 41 01 b9 51 00 00 00 90 00 } //2
		$a_03_1 = {8b 45 ec 6b f6 28 8b 51 14 0f 80 90 01 04 03 f0 8b 41 10 0f 80 90 01 04 2b f2 3b f0 72 0c 90 00 } //1
		$a_03_2 = {8b 85 d4 fe ff ff 8b 8d cc fd ff ff 90 02 06 03 c1 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}