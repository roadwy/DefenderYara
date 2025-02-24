
rule VirTool_Win64_Shrinj_A{
	meta:
		description = "VirTool:Win64/Shrinj.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 67 20 44 4c 4c 73 20 2d 20 70 61 74 69 65 6e 63 65 20 70 6c } //1 ng DLLs - patience pl
		$a_01_1 = {1b 5b 33 31 6d e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 20 20 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}