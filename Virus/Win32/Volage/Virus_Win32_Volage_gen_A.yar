
rule Virus_Win32_Volage_gen_A{
	meta:
		description = "Virus:Win32/Volage.gen!A,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {77 72 69 74 74 65 6e 20 62 79 20 44 52 2d 45 46 } //0a 00 
		$a_01_1 = {32 30 30 34 20 44 52 2d 45 46 } //01 00 
		$a_01_2 = {4d 65 73 73 61 67 65 42 6f 78 41 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00 
		$a_01_4 = {57 69 6e 45 78 65 63 } //00 00 
	condition:
		any of ($a_*)
 
}