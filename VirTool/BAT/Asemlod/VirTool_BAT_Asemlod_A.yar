
rule VirTool_BAT_Asemlod_A{
	meta:
		description = "VirTool:BAT/Asemlod.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 5a 13 90 01 01 11 90 01 01 17 58 13 90 01 01 11 90 01 01 11 90 01 01 32 90 01 01 09 11 90 01 01 07 11 90 01 01 91 5a 58 0d 11 90 01 01 17 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}