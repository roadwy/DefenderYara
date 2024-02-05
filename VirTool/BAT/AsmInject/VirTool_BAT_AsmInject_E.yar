
rule VirTool_BAT_AsmInject_E{
	meta:
		description = "VirTool:BAT/AsmInject.E,SIGNATURE_TYPE_PEHSTR,64 00 64 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 64 00 65 00 64 00 20 00 66 00 6f 00 72 00 20 00 50 00 61 00 72 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 2e 00 20 00 52 00 65 00 76 00 69 00 73 00 69 00 6f 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}