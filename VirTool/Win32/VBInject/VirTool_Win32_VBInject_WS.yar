
rule VirTool_Win32_VBInject_WS{
	meta:
		description = "VirTool:Win32/VBInject.WS,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 00 65 00 64 00 69 00 63 00 61 00 64 00 6f 00 73 00 20 00 41 00 6c 00 20 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 } //1 Dedicados Al Malware
		$a_01_1 = {43 00 3a 00 5c 00 43 00 61 00 72 00 74 00 6f 00 6f 00 20 00 4c 00 6f 00 73 00 61 00 5c 00 43 00 61 00 72 00 74 00 6f 00 6f 00 6e 00 54 00 2e 00 76 00 62 00 70 00 } //1 C:\Cartoo Losa\CartoonT.vbp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}