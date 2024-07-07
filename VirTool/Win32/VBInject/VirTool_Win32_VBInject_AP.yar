
rule VirTool_Win32_VBInject_AP{
	meta:
		description = "VirTool:Win32/VBInject.AP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 79 74 49 6e 00 00 00 62 79 74 50 61 73 73 77 6f 72 64 } //1
		$a_01_1 = {28 34 ff 02 00 6c 64 ff 6c 68 ff 0b 04 00 0c 00 23 30 ff 2a 23 2c ff 0a 05 00 04 00 e8 0b 06 00 04 00 23 28 ff 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}