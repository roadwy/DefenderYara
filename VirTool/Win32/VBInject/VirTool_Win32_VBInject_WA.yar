
rule VirTool_Win32_VBInject_WA{
	meta:
		description = "VirTool:Win32/VBInject.WA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1c 20 a4 00 a3 00 53 01 d6 00 18 20 d3 00 c6 00 d7 00 7e 01 a4 00 9d 00 1d 20 bc 00 22 20 c6 00 e4 00 d7 00 a8 00 3a 20 00 00 00 00 12 00 00 00 } //1
		$a_01_1 = {73 43 61 6c 6c 5f 4d 33 00 00 00 00 73 44 65 63 6f 64 65 72 4d 33 00 00 73 49 6e 66 6f 5f 00 00 73 50 61 74 68 43 61 73 65 00 00 00 41 76 69 72 5f 4d 33 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}