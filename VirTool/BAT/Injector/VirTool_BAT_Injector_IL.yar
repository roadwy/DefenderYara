
rule VirTool_BAT_Injector_IL{
	meta:
		description = "VirTool:BAT/Injector.IL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 65 76 65 72 61 67 65 2e 65 78 65 00 6c 65 76 65 72 61 67 65 00 } //01 00 
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d 00 53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 00 } //01 00 
		$a_01_2 = {44 6f 63 75 6d 65 6e 74 20 53 63 61 6e 6e 65 72 00 } //01 00 
		$a_01_3 = {13 6c 65 76 65 72 61 67 65 2e 50 72 6f 70 65 72 74 69 65 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}