
rule VirTool_BAT_Injector_IF{
	meta:
		description = "VirTool:BAT/Injector.IF,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {17 58 0c 08 07 61 0c 06 16 07 } //0a 00  堗ࠌ愇،ܖ
		$a_01_1 = {00 4c 6f 61 64 6d 65 00 52 65 67 6d 65 00 57 61 69 74 4f 6e 65 00 } //0a 00  䰀慯浤e敒浧e慗瑩湏e
		$a_01_2 = {00 50 65 72 73 69 73 74 65 6e 63 65 00 46 69 6c 65 70 65 72 73 69 73 74 65 6e 63 65 00 } //01 00 
		$a_01_3 = {00 4c 6f 61 64 6d 65 00 } //01 00  䰀慯浤e
		$a_01_4 = {00 52 65 67 6d 65 00 } //00 00 
		$a_00_5 = {5d 04 00 00 a4 6c 03 80 5c 1f 00 } //00 a5 
	condition:
		any of ($a_*)
 
}