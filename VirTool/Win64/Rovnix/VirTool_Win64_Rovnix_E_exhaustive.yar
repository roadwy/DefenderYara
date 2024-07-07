
rule VirTool_Win64_Rovnix_E_exhaustive{
	meta:
		description = "VirTool:Win64/Rovnix.E!exhaustive,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 85 c9 74 08 4d 85 c9 74 0e 49 ff e1 4d 85 c0 74 06 48 8b ca 49 ff e0 b8 0d 00 00 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}