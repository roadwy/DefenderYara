
rule Worm_Win32_Olufus_A{
	meta:
		description = "Worm:Win32/Olufus.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {4f 00 6c 00 66 00 56 00 69 00 72 00 31 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 } //01 00  OlfVir1Project
		$a_03_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 90 02 20 2e 00 64 00 6f 00 63 00 90 00 } //01 00 
		$a_03_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 90 02 20 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_03_3 = {5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 90 02 40 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_03_4 = {2e 00 65 00 78 00 65 00 90 02 10 53 00 74 00 61 00 72 00 74 00 75 00 70 00 90 02 10 53 00 70 00 65 00 63 00 69 00 61 00 6c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 90 00 } //01 00 
		$a_03_5 = {44 00 72 00 69 00 76 00 65 00 4c 00 65 00 74 00 74 00 65 00 72 00 90 02 20 47 00 65 00 74 00 46 00 6f 00 6c 00 64 00 65 00 72 00 90 00 } //01 00 
		$a_03_6 = {54 00 69 00 6d 00 65 00 72 00 53 00 70 00 72 00 65 00 61 00 64 00 69 00 6e 00 67 00 41 00 63 00 74 00 69 00 6f 00 6e 00 90 02 10 44 00 72 00 69 00 76 00 65 00 90 00 } //00 00 
		$a_00_7 = {5d 04 00 00 81 } //3f 03 
	condition:
		any of ($a_*)
 
}