
rule TrojanDropper_Win32_Renos_HH{
	meta:
		description = "TrojanDropper:Win32/Renos.HH,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0c 00 00 05 00 "
		
	strings :
		$a_03_0 = {1c 40 3d 00 01 00 00 72 f4 90 02 10 68 ff ff 90 01 02 68 ff ff 90 00 } //02 00 
		$a_03_1 = {40 00 68 ff ff 90 01 02 68 ff ff 90 00 } //01 00 
		$a_01_2 = {68 82 00 00 00 } //01 00 
		$a_02_3 = {6a 02 57 6a fc 56 ff 15 90 01 03 00 90 00 } //01 00 
		$a_00_4 = {43 72 65 61 74 65 54 68 72 65 61 64 00 } //01 00 
		$a_00_5 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 00 } //01 00 
		$a_00_6 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 00 } //01 00 
		$a_00_7 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 00 } //01 00  楆摮敒潳牵散A
		$a_00_8 = {44 65 6c 65 74 65 46 69 6c 65 41 00 } //01 00  敄敬整楆敬A
		$a_00_9 = {53 65 74 46 69 6c 65 50 6f 69 6e 74 65 72 00 } //01 00 
		$a_00_10 = {57 49 4e 49 4e 45 54 2e 44 4c 4c 00 } //01 00 
		$a_00_11 = {4d 53 56 43 50 36 30 2e 64 6c 6c 00 } //00 00  卍䍖㙐⸰汤l
	condition:
		any of ($a_*)
 
}