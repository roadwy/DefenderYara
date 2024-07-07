
rule VirTool_Win32_VBInject_UN{
	meta:
		description = "VirTool:Win32/VBInject.UN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 66 66 73 65 74 20 4c 6f 63 61 74 6f 72 20 56 33 20 4d 6f 64 20 42 79 20 44 72 2e 47 33 4e 49 55 53 } //1 Offset Locator V3 Mod By Dr.G3NIUS
		$a_01_1 = {41 56 46 75 63 6b 65 72 20 4d 65 74 68 6f 64 } //1 AVFucker Method
		$a_01_2 = {46 55 44 53 4f 6e 6c 79 2e 63 6f 6d 2e 61 72 } //1 FUDSOnly.com.ar
		$a_01_3 = {49 6e 64 65 74 65 63 74 61 62 6c 65 73 2e 6e 65 74 } //1 Indetectables.net
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}