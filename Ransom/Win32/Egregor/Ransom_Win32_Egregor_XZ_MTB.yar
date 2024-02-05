
rule Ransom_Win32_Egregor_XZ_MTB{
	meta:
		description = "Ransom:Win32/Egregor.XZ!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 4f 55 44 20 21 21 21 21 2e 2e 2e } //01 00 
		$a_01_1 = {45 6c 6f 6e 20 4d 75 73 6b 20 32 30 32 34 21 20 54 6f 20 74 68 65 20 66 75 74 75 72 65 21 21 21 } //01 00 
		$a_01_2 = {43 3a 5c 64 64 64 64 73 73 5c 65 65 65 72 72 72 5c 69 75 66 79 68 66 6a 2e 70 79 } //01 00 
		$a_01_3 = {43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 61 72 79 41 } //01 00 
		$a_01_4 = {2d 00 2d 00 6c 00 6f 00 75 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}