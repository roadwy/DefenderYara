
rule VirTool_Win32_VBInject_FJ{
	meta:
		description = "VirTool:Win32/VBInject.FJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 53 00 74 00 75 00 62 00 20 00 6e 00 75 00 65 00 76 00 6f 00 20 00 44 00 55 00 4e 00 45 00 44 00 41 00 49 00 2e 00 76 00 62 00 70 00 } //2 \Stub nuevo DUNEDAI.vbp
		$a_00_1 = {53 00 77 00 61 00 73 00 68 00 4c 00 61 00 62 00 73 00 } //1 SwashLabs
		$a_01_2 = {44 65 63 72 79 70 74 46 69 6c 65 } //1 DecryptFile
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}