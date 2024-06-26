
rule HackTool_Win64_Edrblok_A{
	meta:
		description = "HackTool:Win64/Edrblok.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 05 00 "
		
	strings :
		$a_80_0 = {3c 62 6c 6f 63 6b 65 64 72 2f } //<blockedr/  05 00 
		$a_80_1 = {45 44 52 53 69 6c 65 6e 63 65 72 } //EDRSilencer  05 00 
		$a_80_2 = {42 6c 6f 63 6b 50 72 6f 63 65 73 73 54 72 61 66 66 69 63 } //BlockProcessTraffic  03 00 
		$a_01_3 = {44 65 74 65 63 74 65 64 20 72 75 6e 6e 69 6e 67 20 45 44 52 20 70 72 6f 63 65 73 73 } //02 00  Detected running EDR process
		$a_01_4 = {69 73 49 6e 45 64 72 50 72 6f 63 65 73 73 4c 69 73 74 } //01 00  isInEdrProcessList
		$a_03_5 = {d1 57 8d c3 90 01 04 a7 05 90 01 04 33 4c 90 01 02 90 90 4f 7f bc ee e6 0e 82 90 00 } //01 00 
		$a_03_6 = {87 1e 8e d7 90 01 04 44 86 90 01 04 a5 4e 90 01 02 94 37 d8 09 ec ef c9 71 90 00 } //01 00 
		$a_03_7 = {3b 39 72 4a 90 01 04 9f 31 90 01 04 bc 44 90 01 02 84 c3 ba 54 dc b3 b6 b4 90 00 } //00 00 
		$a_00_8 = {5d 04 00 00 f7 5a } //06 80 
	condition:
		any of ($a_*)
 
}