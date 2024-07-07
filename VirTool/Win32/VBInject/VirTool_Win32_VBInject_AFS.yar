
rule VirTool_Win32_VBInject_AFS{
	meta:
		description = "VirTool:Win32/VBInject.AFS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f d8 d1 66 0f 65 ed 0f fd d3 31 c1 81 f9 89 d9 89 d9 0f 85 78 ff ff ff } //1
		$a_01_1 = {41 0f d5 ff 66 0f fd f3 0f e2 f1 0f 62 da 0f db eb 66 0f 69 ef 66 0f ec ed 83 c1 03 } //1
		$a_01_2 = {0f dc ec 66 0f 66 f3 0f f5 ce 0f 6a e8 81 7c 0d fc 95 95 95 95 0f 85 5c ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}