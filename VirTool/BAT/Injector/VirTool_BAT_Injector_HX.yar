
rule VirTool_BAT_Injector_HX{
	meta:
		description = "VirTool:BAT/Injector.HX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {58 6e 16 28 90 01 04 6a 5f 69 95 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}