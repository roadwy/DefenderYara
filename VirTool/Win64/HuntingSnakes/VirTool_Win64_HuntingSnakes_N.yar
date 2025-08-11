
rule VirTool_Win64_HuntingSnakes_N{
	meta:
		description = "VirTool:Win64/HuntingSnakes.N,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 68 61 6e 75 73 68 67 6f 77 64 61 } //1 dhanushgowda
		$a_01_1 = {2e 64 6c 6c 00 63 6f 6f 6c 62 6f 79 } //1 搮汬挀潯扬祯
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}