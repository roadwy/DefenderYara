
rule VirTool_BAT_Obfuscator_RunPE_DzkiLLeR{
	meta:
		description = "VirTool:BAT/Obfuscator.RunPE.DzkiLLeR,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 7a 6b 69 4c 4c 65 52 } //1 DzkiLLeR
	condition:
		((#a_01_0  & 1)*1) >=1
 
}