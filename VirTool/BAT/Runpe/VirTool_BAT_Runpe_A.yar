
rule VirTool_BAT_Runpe_A{
	meta:
		description = "VirTool:BAT/Runpe.A,SIGNATURE_TYPE_PEHSTR,64 00 64 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 50 45 } //1 RunPE
		$a_01_1 = {50 45 42 50 61 74 63 68 65 72 } //1 PEBPatcher
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=100
 
}