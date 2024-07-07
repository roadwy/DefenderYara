
rule VirTool_Win32_VBInject_DX{
	meta:
		description = "VirTool:Win32/VBInject.DX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 00 3a 00 5c 00 53 00 31 00 5c 00 53 00 32 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 43 00 43 00 2e 00 76 00 62 00 70 00 } //2 D:\S1\S2\ProjectCC.vbp
		$a_01_1 = {6d 6f 64 53 68 6f 72 74 63 75 74 73 } //1 modShortcuts
		$a_01_2 = {6d 6f 64 43 50 55 49 6e 66 6f } //1 modCPUInfo
		$a_01_3 = {63 6c 73 48 75 66 66 6d 61 6e } //1 clsHuffman
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}