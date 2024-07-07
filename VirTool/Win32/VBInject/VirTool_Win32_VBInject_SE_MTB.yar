
rule VirTool_Win32_VBInject_SE_MTB{
	meta:
		description = "VirTool:Win32/VBInject.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {85 ff d9 d0 90 90 90 90 d9 d0 d9 d0 75 90 0a 40 00 8b 14 38 90 02 10 e8 90 02 20 52 90 02 10 85 ff d9 d0 90 00 } //1
		$a_03_1 = {64 a1 30 00 00 00 90 02 20 e9 90 01 02 00 00 90 00 } //1
		$a_03_2 = {83 fb 00 7f 90 01 01 90 02 10 83 c4 78 90 02 10 ff e0 90 0a 70 00 8b 14 1f 90 02 10 56 90 02 10 33 14 24 90 02 10 5e 90 02 10 89 14 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}