
rule VirTool_BAT_NetInject_B{
	meta:
		description = "VirTool:BAT/NetInject.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 85 02 a0 60 e8 90 01 02 ff ff 68 84 2a ab 54 50 e8 90 01 02 ff ff ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_BAT_NetInject_B_2{
	meta:
		description = "VirTool:BAT/NetInject.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 67 4c 6f 61 64 65 72 } //01 00  dgLoader
		$a_01_1 = {6c 6f 61 64 65 72 5f 61 72 72 61 79 } //01 00  loader_array
		$a_01_2 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //00 00  GetDelegateForFunctionPointer
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}