
rule Ransom_Win32_Reveton_F{
	meta:
		description = "Ransom:Win32/Reveton.F,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 6c 6e 6b 00 } //01 00 
		$a_00_1 = {4e 6f 50 72 6f 74 65 63 74 65 64 4d 6f 64 65 42 61 6e 6e 65 72 } //03 00  NoProtectedModeBanner
		$a_03_2 = {46 69 6c 65 4d 65 6d 2e 64 6c 6c 00 90 02 03 64 65 66 61 75 6c 74 90 00 } //02 00 
		$a_00_3 = {00 4c 6f 63 6b 2e 64 6c 6c } //03 00 
		$a_03_4 = {8b ce ba 01 00 00 00 d3 e2 4a 23 54 24 28 0f b7 4c 24 42 03 d1 8b 4c 24 34 8b 14 91 89 54 24 40 e9 90 01 02 ff ff 8b 04 24 c7 40 18 90 01 04 8b 44 24 04 c7 00 12 00 00 00 eb 90 01 01 f7 c6 40 00 00 00 75 90 01 01 8b ce ba 01 00 00 00 d3 e2 4a 23 54 24 28 0f b7 44 24 42 03 d0 8b 4c 24 30 8b 14 91 89 54 24 40 90 00 } //02 00 
		$a_00_5 = {7e 15 00 00 07 1b } //79 d1 
	condition:
		any of ($a_*)
 
}