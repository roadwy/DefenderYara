
rule Ransom_Win32_Clop_PC_MTB{
	meta:
		description = "Ransom:Win32/Clop.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 43 00 49 00 6f 00 70 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_00_1 = {73 00 72 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_01_2 = {52 00 43 00 5f 00 44 00 41 00 54 00 41 00 42 00 49 00 47 00 42 00 41 00 43 00 4b 00 } //01 00 
		$a_00_3 = {53 52 52 65 6d 6f 76 65 52 65 73 74 6f 72 65 50 6f 69 6e 74 } //01 00 
		$a_01_4 = {4d 61 6b 65 4d 6f 6e 65 79 46 72 6f 6d 41 69 72 23 37 37 37 } //0a 00 
		$a_02_5 = {b9 4f 00 00 00 66 89 4d 90 01 01 ba 43 00 00 00 66 89 55 90 01 01 b8 58 00 00 00 66 89 45 90 01 01 90 02 80 b8 2e 00 00 00 66 89 85 90 01 04 b9 44 00 00 00 66 89 8d 90 01 04 ba 4c 00 00 00 66 89 95 90 01 04 b8 4c 00 00 00 66 89 85 90 01 04 90 02 80 b8 2e 00 00 00 66 89 45 90 01 01 b9 43 00 00 00 66 89 4d 90 01 01 ba 49 00 00 00 66 89 55 90 01 01 b8 4f 00 00 00 66 89 45 90 01 01 b9 50 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}