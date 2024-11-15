
rule VirTool_Win64_Stardustsec_A{
	meta:
		description = "VirTool:Win64/Stardustsec.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 48 89 e6 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 89 f4 5e c3 e8 ?? ?? ?? ?? c3 48 8b 04 24 48 83 e8 1b c3 } //1
		$a_01_1 = {48 8b 04 24 48 83 c0 0b c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}