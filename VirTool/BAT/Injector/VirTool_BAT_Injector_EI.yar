
rule VirTool_BAT_Injector_EI{
	meta:
		description = "VirTool:BAT/Injector.EI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 71 30 33 4e 64 6f 6a 39 38 79 43 58 32 56 6d 71 30 68 6e 36 4a 75 33 73 6f 00 } //1
		$a_01_1 = {00 68 6b 6a 4f 32 33 37 36 47 73 35 36 39 67 58 32 00 } //1 栀橫㉏㜳䜶㕳㤶塧2
		$a_01_2 = {00 42 6f 74 6f 6d 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}