
rule Ransom_Win32_Magniber_A_{
	meta:
		description = "Ransom:Win32/Magniber.A!!Magniber.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 33 c0 4c 8b d1 b8 90 01 01 00 00 00 0f 05 c3 90 00 } //01 00 
		$a_03_1 = {e8 00 00 00 00 58 eb 90 02 80 48 83 e8 05 eb 90 02 80 48 2d 90 01 03 00 eb 90 00 } //01 00 
		$a_03_2 = {b9 4c 77 d6 07 e8 90 01 04 48 8d 90 02 08 ff d0 b9 49 f7 02 78 4c 8b e0 e8 90 00 } //01 00 
		$a_03_3 = {ff d0 b9 3a 56 29 a8 e8 90 01 04 b9 77 87 2a f1 48 89 90 01 02 e8 90 01 04 b9 d3 6b 6e d4 90 00 } //01 00 
		$a_03_4 = {74 6d dd 6e c7 45 90 01 01 07 c0 75 4e 48 c7 90 01 02 00 02 00 00 48 89 90 01 02 c7 44 90 01 02 00 10 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Magniber_A__2{
	meta:
		description = "Ransom:Win32/Magniber.A!!Magniber.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 90 01 04 48 8b e6 5e c3 90 02 30 b8 90 01 02 00 00 0f 05 c3 90 02 30 b8 90 01 02 00 00 0f 05 c3 90 00 } //01 00 
		$a_03_1 = {e8 00 00 00 00 58 48 83 e8 05 48 2d 90 01 03 00 c3 90 00 } //01 00 
		$a_03_2 = {b9 4c 77 d6 07 e8 90 01 04 48 8d 90 02 08 ff d0 b9 49 f7 02 78 4c 8b e0 e8 90 00 } //01 00 
		$a_03_3 = {ff d0 b9 3a 56 29 a8 e8 90 01 04 b9 77 87 2a f1 48 89 90 01 02 e8 90 01 04 b9 d3 6b 6e d4 90 00 } //01 00 
		$a_03_4 = {74 6d dd 6e c7 45 90 01 01 07 c0 75 4e 48 c7 90 01 02 00 02 00 00 48 89 90 01 02 c7 44 90 01 02 00 10 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Magniber_A__3{
	meta:
		description = "Ransom:Win32/Magniber.A!!Magniber.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 90 01 04 48 8b e6 5e c3 90 02 30 b8 90 01 02 00 00 0f 05 c3 90 02 30 b8 90 01 02 00 00 0f 05 c3 90 00 } //01 00 
		$a_03_1 = {e8 00 00 00 00 58 eb 90 02 30 48 83 e8 05 eb 90 02 30 48 2d 90 01 03 00 eb 90 00 } //01 00 
		$a_03_2 = {b9 4c 77 d6 07 e8 90 01 04 48 8d 90 02 08 ff d0 b9 49 f7 02 78 4c 8b e0 e8 90 00 } //01 00 
		$a_03_3 = {ff d0 b9 3a 56 29 a8 e8 90 01 04 b9 77 87 2a f1 48 89 90 01 02 e8 90 01 04 b9 d3 6b 6e d4 90 00 } //01 00 
		$a_03_4 = {74 6d dd 6e c7 45 90 01 01 07 c0 75 4e 48 c7 90 01 02 00 02 00 00 48 89 90 01 02 c7 44 90 01 02 00 10 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Magniber_A__4{
	meta:
		description = "Ransom:Win32/Magniber.A!!Magniber.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 90 01 04 48 8b e6 5e c3 90 02 06 b8 90 01 02 00 00 0f 05 c3 90 02 06 b8 90 01 02 00 00 0f 05 c3 90 00 } //01 00 
		$a_00_1 = {77 00 69 00 6e 00 6e 00 74 00 00 00 2e 00 00 00 2e 00 2e 00 00 00 5c 00 00 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 68 00 74 00 6d 00 6c 00 00 00 } //01 00 
		$a_00_2 = {3d 20 6e 65 77 20 41 72 72 61 79 28 } //01 00  = new Array(
		$a_00_3 = {66 72 6f 6d 43 68 61 72 43 6f 64 65 } //01 00  fromCharCode
		$a_03_4 = {e8 00 00 00 00 58 48 83 e8 05 48 2d 90 01 02 00 00 c3 90 00 } //01 00 
		$a_03_5 = {b9 4c 77 d6 07 e8 90 01 04 48 8d 90 02 08 ff d0 b9 49 f7 02 78 4c 8b e0 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}