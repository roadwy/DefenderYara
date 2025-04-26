
rule VirTool_Win32_OfsBuilz_A_MTB{
	meta:
		description = "VirTool:Win32/OfsBuilz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {4f 66 66 65 6e 73 69 76 65 50 69 70 65 6c 69 6e 65 } //1 OffensivePipeline
		$a_81_1 = {4f 66 66 65 6e 73 69 76 65 50 69 70 65 6c 69 6e 65 2e 64 6c 6c } //1 OffensivePipeline.dll
		$a_81_2 = {68 6f 73 74 66 78 72 2e 64 6c 6c } //1 hostfxr.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}