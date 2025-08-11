
rule VirTool_Win64_HBPAmsibyp_A{
	meta:
		description = "VirTool:Win64/HBPAmsibyp.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 01 48 8b f1 bd 01 00 00 00 81 38 04 00 00 80 } //1
		$a_03_1 = {48 8b 83 98 00 00 00 48 8b 50 30 ?? ?? ?? ?? ?? ?? ?? c7 02 00 00 00 00 81 4b 44 00 00 01 00 48 89 83 f8 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}