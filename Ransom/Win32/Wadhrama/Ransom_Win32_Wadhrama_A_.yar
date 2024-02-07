
rule Ransom_Win32_Wadhrama_A_{
	meta:
		description = "Ransom:Win32/Wadhrama.A!!Wadhrama.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 08 00 00 03 00 "
		
	strings :
		$a_00_0 = {3a 5c 63 72 79 73 69 73 5c 52 65 6c 65 61 73 65 5c 50 44 42 5c 70 61 79 6c 6f 61 64 2e 70 64 62 } //03 00  :\crysis\Release\PDB\payload.pdb
		$a_00_1 = {63 6f 6e 20 63 70 20 73 65 6c 65 63 74 3d 31 32 35 31 0a 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //01 00 
		$a_01_2 = {8b 4d f4 33 44 0d c8 8b 55 f4 89 44 15 c8 8b 45 f4 83 c0 04 89 45 f4 83 7d f4 20 } //01 00 
		$a_00_3 = {44 00 65 00 6e 00 69 00 65 00 64 00 20 00 49 00 4e 00 46 00 4f 00 52 00 4d 00 41 00 54 00 49 00 4f 00 4e 00 2e 00 74 00 78 00 74 00 00 00 } //01 00 
		$a_00_4 = {3b 00 2e 00 6d 00 78 00 6c 00 3b 00 2e 00 6d 00 79 00 64 00 3b 00 2e 00 6d 00 79 00 69 00 3b 00 2e 00 6e 00 65 00 66 00 3b 00 2e 00 6e 00 72 00 77 00 3b 00 2e 00 6f 00 62 00 6a 00 3b 00 2e 00 } //01 00  ;.mxl;.myd;.myi;.nef;.nrw;.obj;.
		$a_00_5 = {63 6f 6e 20 63 70 20 73 65 6c 65 63 74 3d 31 32 35 31 } //01 00  con cp select=1251
		$a_00_6 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //ce ff  delete shadows /all /quiet
		$a_00_7 = {6f 75 74 5c 52 65 6c 65 61 73 65 5c 33 36 30 45 6e 74 43 6c 69 65 6e 74 2e 70 64 62 } //00 00  out\Release\360EntClient.pdb
	condition:
		any of ($a_*)
 
}