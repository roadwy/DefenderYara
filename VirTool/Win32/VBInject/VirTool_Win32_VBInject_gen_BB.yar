
rule VirTool_Win32_VBInject_gen_BB{
	meta:
		description = "VirTool:Win32/VBInject.gen!BB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 11 00 00 00 8b 85 a8 fe ff ff 03 85 9c fe ff ff } //1
		$a_01_1 = {74 00 78 00 65 00 74 00 6e 00 6f 00 43 00 64 00 61 00 65 00 72 00 68 00 54 00 74 00 65 00 53 00 00 00 } //1
		$a_01_2 = {31 45 d4 8b 45 c0 31 45 d8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}