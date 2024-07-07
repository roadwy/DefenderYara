
rule VirTool_BAT_Asemlod_C{
	meta:
		description = "VirTool:BAT/Asemlod.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 00 2e 00 38 00 4f 00 84 76 84 76 79 00 84 76 84 76 84 76 84 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}