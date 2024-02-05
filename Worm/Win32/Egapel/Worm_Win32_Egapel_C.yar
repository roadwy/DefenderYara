
rule Worm_Win32_Egapel_C{
	meta:
		description = "Worm:Win32/Egapel.C,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0c 00 0b 00 00 05 00 "
		
	strings :
		$a_01_0 = {83 f8 05 7c ed c6 06 e9 89 7e 01 } //05 00 
		$a_01_1 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 57 00 } //01 00 
		$a_00_2 = {52 00 45 00 43 00 59 00 43 00 4c 00 45 00 52 00 2e 00 6c 00 6e 00 6b 00 } //01 00 
		$a_00_3 = {70 00 61 00 67 00 65 00 66 00 69 00 6c 00 65 00 2e 00 73 00 79 00 73 00 2e 00 6c 00 6e 00 6b 00 } //01 00 
		$a_00_4 = {62 00 6f 00 6f 00 74 00 2e 00 69 00 6e 00 69 00 2e 00 6c 00 6e 00 6b 00 } //01 00 
		$a_00_5 = {49 00 4f 00 2e 00 53 00 59 00 53 00 2e 00 6c 00 6e 00 6b 00 } //01 00 
		$a_00_6 = {4e 00 54 00 44 00 45 00 54 00 45 00 43 00 54 00 2e 00 43 00 4f 00 4d 00 2e 00 6c 00 6e 00 6b 00 } //01 00 
		$a_00_7 = {53 00 79 00 73 00 74 00 65 00 6d 00 20 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 20 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 6c 00 6e 00 6b 00 } //01 00 
		$a_00_8 = {64 00 65 00 73 00 74 00 6f 00 70 00 2e 00 69 00 6e 00 69 00 2e 00 6c 00 6e 00 6b 00 } //01 00 
		$a_00_9 = {57 00 43 00 48 00 2e 00 43 00 4e 00 2e 00 6c 00 6e 00 6b 00 } //01 00 
		$a_00_10 = {77 00 69 00 6e 00 6e 00 74 00 2e 00 62 00 6d 00 70 00 2e 00 6c 00 6e 00 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}