
rule VirTool_BAT_CeeInject_gen_C{
	meta:
		description = "VirTool:BAT/CeeInject.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_1 = {08 11 11 08 58 46 52 08 46 11 14 61 13 0a 08 11 0a 52 11 0a 11 15 61 13 09 08 11 09 52 08 11 09 11 16 61 52 11 04 17 58 13 04 08 17 58 0c 11 04 11 06 20 00 66 06 00 58 4a 37 c5 } //00 00 
	condition:
		any of ($a_*)
 
}