
rule VirTool_BAT_Runpe_A{
	meta:
		description = "VirTool:BAT/Runpe.A,SIGNATURE_TYPE_PEHSTR,64 00 64 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 6e 50 45 } //01 00 
		$a_01_1 = {50 45 42 50 61 74 63 68 65 72 } //00 00 
		$a_01_2 = {00 5d } //04 00 
	condition:
		any of ($a_*)
 
}