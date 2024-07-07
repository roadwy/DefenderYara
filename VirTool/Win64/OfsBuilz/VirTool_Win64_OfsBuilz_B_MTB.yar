
rule VirTool_Win64_OfsBuilz_B_MTB{
	meta:
		description = "VirTool:Win64/OfsBuilz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {4f 66 66 65 6e 73 69 76 65 50 69 70 65 6c 69 6e 65 } //1 OffensivePipeline
		$a_81_1 = {4f 66 66 65 6e 73 69 76 65 50 69 70 65 6c 69 6e 65 2e 64 6c 6c } //1 OffensivePipeline.dll
		$a_81_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 61 65 74 73 75 } //1 github.com/aetsu
		$a_81_3 = {73 6f 63 6b 65 74 } //1 socket
		$a_81_4 = {53 68 65 6c 6c } //1 Shell
		$a_81_5 = {72 65 71 75 65 73 74 65 64 50 72 69 76 69 6c 65 67 65 73 } //1 requestedPrivileges
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}