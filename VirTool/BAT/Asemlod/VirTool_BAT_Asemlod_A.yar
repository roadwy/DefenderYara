
rule VirTool_BAT_Asemlod_A{
	meta:
		description = "VirTool:BAT/Asemlod.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 5a 13 ?? 11 ?? 17 58 13 ?? 11 ?? 11 ?? 32 ?? 09 11 ?? 07 11 ?? 91 5a 58 0d 11 ?? 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}