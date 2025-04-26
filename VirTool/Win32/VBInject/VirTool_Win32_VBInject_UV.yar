
rule VirTool_Win32_VBInject_UV{
	meta:
		description = "VirTool:Win32/VBInject.UV,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 00 5c 00 4e 00 61 00 72 00 75 00 74 00 6f 00 5c 00 55 00 64 00 74 00 6f 00 6f 00 6c 00 73 00 5c 00 55 00 64 00 74 00 6f 00 6f 00 6c 00 73 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 :\Naruto\Udtools\Udtools\Project1.vbp
		$a_01_1 = {5b 00 4e 00 61 00 72 00 75 00 74 00 6f 00 56 00 53 00 73 00 61 00 73 00 75 00 6b 00 65 00 5d 00 } //1 [NarutoVSsasuke]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}