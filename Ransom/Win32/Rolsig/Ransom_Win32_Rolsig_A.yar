
rule Ransom_Win32_Rolsig_A{
	meta:
		description = "Ransom:Win32/Rolsig.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 8b c3 43 8b ca 83 e0 01 8b c2 75 0b c1 e1 05 d1 e8 33 c8 33 ce eb 0c c1 e1 09 c1 e8 03 33 c8 33 ce f7 d1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Rolsig_A_2{
	meta:
		description = "Ransom:Win32/Rolsig.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 61 72 64 77 61 72 65 42 72 65 61 6b 70 6f 69 6e 74 73 } //01 00 
		$a_03_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 90 03 03 03 50 45 42 41 50 49 90 00 } //01 00 
		$a_00_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 41 50 49 } //01 00 
		$a_00_3 = {49 73 41 6e 79 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_00_4 = {50 00 69 00 70 00 70 00 6f 00 20 00 43 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 65 00 72 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}