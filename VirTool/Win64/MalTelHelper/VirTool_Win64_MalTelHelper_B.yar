
rule VirTool_Win64_MalTelHelper_B{
	meta:
		description = "VirTool:Win64/MalTelHelper.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 70 6c 73 74 61 72 74 } //1 pplstart
		$a_01_1 = {6b 72 6e 6c 6f 61 64 } //1 krnload
		$a_01_2 = {64 6c 6c 63 61 6c 6c 73 74 61 63 6b } //1 dllcallstack
		$a_01_3 = {64 6c 6c 72 65 61 64 65 72 } //1 dllreader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}