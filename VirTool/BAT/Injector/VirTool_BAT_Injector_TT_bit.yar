
rule VirTool_BAT_Injector_TT_bit{
	meta:
		description = "VirTool:BAT/Injector.TT!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e b7 17 da 90 01 01 da 03 90 01 01 91 90 01 01 61 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 90 01 01 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 8e b7 5d 91 61 9c 90 01 01 17 d6 0d 90 00 } //01 00 
		$a_01_1 = {00 72 70 2e 64 6c 6c 00 00 00 00 0f 61 00 70 00 70 00 64 00 61 00 74 00 61 00 } //01 00 
		$a_01_2 = {43 6f 6c 6f 72 00 49 6d 61 67 65 00 67 65 74 5f 57 69 64 74 68 00 67 65 74 5f 48 65 69 67 68 74 } //01 00  潃潬r浉条e敧彴楗瑤h敧彴效杩瑨
		$a_03_3 = {47 00 65 00 74 00 50 00 69 00 78 00 65 00 6c 00 90 01 02 52 00 90 01 02 47 00 90 01 02 42 00 90 00 } //01 00 
		$a_01_4 = {00 47 65 74 50 72 6f 63 65 73 73 42 79 49 64 00 4b 69 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}