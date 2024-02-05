
rule VirTool_BAT_Injector_DP_bit{
	meta:
		description = "VirTool:BAT/Injector.DP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 61 70 74 65 72 4f 6e 65 00 49 6e 74 72 6f } //01 00 
		$a_01_1 = {72 33 74 72 69 33 76 33 52 75 6e 50 33 } //00 00 
	condition:
		any of ($a_*)
 
}