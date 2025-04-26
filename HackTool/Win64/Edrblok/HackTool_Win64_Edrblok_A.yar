
rule HackTool_Win64_Edrblok_A{
	meta:
		description = "HackTool:Win64/Edrblok.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_80_0 = {3c 62 6c 6f 63 6b 65 64 72 2f } //<blockedr/  5
		$a_80_1 = {45 44 52 53 69 6c 65 6e 63 65 72 } //EDRSilencer  5
		$a_80_2 = {42 6c 6f 63 6b 50 72 6f 63 65 73 73 54 72 61 66 66 69 63 } //BlockProcessTraffic  5
		$a_01_3 = {44 65 74 65 63 74 65 64 20 72 75 6e 6e 69 6e 67 20 45 44 52 20 70 72 6f 63 65 73 73 } //3 Detected running EDR process
		$a_01_4 = {69 73 49 6e 45 64 72 50 72 6f 63 65 73 73 4c 69 73 74 } //2 isInEdrProcessList
		$a_03_5 = {d1 57 8d c3 ?? ?? ?? ?? a7 05 ?? ?? ?? ?? 33 4c ?? ?? 90 90 4f 7f bc ee e6 0e 82 } //1
		$a_03_6 = {87 1e 8e d7 ?? ?? ?? ?? 44 86 ?? ?? ?? ?? a5 4e ?? ?? 94 37 d8 09 ec ef c9 71 } //1
		$a_03_7 = {3b 39 72 4a ?? ?? ?? ?? 9f 31 ?? ?? ?? ?? bc 44 ?? ?? 84 c3 ba 54 dc b3 b6 b4 } //1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1) >=11
 
}