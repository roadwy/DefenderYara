
rule VirTool_Win32_VBInject_gen_CB{
	meta:
		description = "VirTool:Win32/VBInject.gen!CB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 95 b4 fe ff ff 8b 85 a8 fe ff ff 03 c2 83 c4 24 ba } //1
		$a_03_1 = {8a 04 0a 8a 14 18 8b 45 ec 8b 48 0c 2b 48 14 a1 90 01 04 30 14 01 90 00 } //1
		$a_01_2 = {c7 45 9c 58 59 59 59 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}