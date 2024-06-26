
rule Ransom_Win32_Sarento_C{
	meta:
		description = "Ransom:Win32/Sarento.C,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {00 72 2b 62 00 77 62 00 90 02 60 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 90 00 } //01 00 
		$a_02_1 = {73 74 3d 00 26 67 75 69 64 3d 00 90 02 40 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 90 00 } //01 00 
		$a_02_2 = {00 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 00 90 02 10 53 68 65 6c 6c 45 78 65 63 75 74 65 41 90 00 } //00 00 
		$a_00_3 = {78 } //df 00  x
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Sarento_C_2{
	meta:
		description = "Ransom:Win32/Sarento.C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 44 24 10 c7 44 24 0c 19 01 02 00 c7 44 24 08 00 00 00 00 90 02 10 c7 04 24 02 00 00 80 90 03 01 02 e8 ff 15 90 01 03 00 83 ec 14 85 c0 90 00 } //0a 00 
		$a_00_1 = {77 00 61 00 6c 00 6c 00 65 00 74 00 00 00 5c 00 00 00 2a 00 00 00 5c 00 2a 00 00 00 2e 00 2e 00 00 00 2e 00 00 00 20 00 3a 00 5c 00 00 00 } //01 00 
		$a_02_2 = {00 72 2b 62 00 77 62 00 90 02 60 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 90 00 } //01 00 
		$a_02_3 = {73 74 3d 00 26 67 75 69 64 3d 00 90 02 40 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 90 00 } //01 00 
		$a_02_4 = {00 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 00 90 02 10 53 68 65 6c 6c 45 78 65 63 75 74 65 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Sarento_C_3{
	meta:
		description = "Ransom:Win32/Sarento.C,SIGNATURE_TYPE_PEHSTR,64 00 64 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 69 63 74 3f 63 75 73 74 3d } //00 00  vict?cust=
	condition:
		any of ($a_*)
 
}