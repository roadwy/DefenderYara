
rule VirTool_BAT_Injector_AI{
	meta:
		description = "VirTool:BAT/Injector.AI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 61 6d 66 69 72 73 74 31 00 67 66 68 72 74 75 00 67 65 74 5f 54 72 6f 65 73 74 65 72 00 54 72 6f 65 73 74 65 72 00 76 61 6c 75 65 00 68 64 74 79 68 74 68 74 00 69 6c 6c 75 69 6f 00 63 68 65 63 6b 6d 65 00 4f 75 74 41 74 74 72 69 62 75 74 65 00 66 73 65 64 72 34 65 68 31 00 6c 6b 6c 70 6b } //00 00 
	condition:
		any of ($a_*)
 
}