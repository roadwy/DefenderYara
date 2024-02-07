
rule TrojanDownloader_O97M_Powdow_DRR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DRR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 66 37 37 36 35 37 32 37 33 36 38 36 35 36 63 36 63 32 30 32 64 37 37 36 39 36 65 32 30 36 38 36 39 36 34 36 34 36 35 36 65 32 30 } //01 00  6f7765727368656c6c202d77696e2068696464656e20
		$a_01_1 = {2e 52 75 6e 20 28 46 75 6c 6c 5f 43 6f 6d 6d 61 6e 64 29 } //01 00  .Run (Full_Command)
		$a_01_2 = {35 37 37 33 36 33 37 32 36 39 37 30 37 34 32 65 35 33 } //01 00  577363726970742e53
		$a_01_3 = {36 38 36 35 36 63 36 63 } //01 00  68656c6c
		$a_01_4 = {2e 6e 41 6d 65 5b 33 2c 31 31 2c 32 5d 2d 6a 6f 49 4e } //01 00  .nAme[3,11,2]-joIN
		$a_01_5 = {43 71 48 77 75 45 51 4f 44 35 57 48 72 56 72 51 59 47 47 68 72 59 38 44 55 58 4a 48 39 43 4c 46 5a 66 } //01 00  CqHwuEQOD5WHrVrQYGGhrY8DUXJH9CLFZf
		$a_01_6 = {37 75 30 42 73 64 69 61 5a 62 37 49 7a 43 33 79 33 41 43 66 42 39 38 4c 4b 59 38 57 65 7a 64 6d 5a 63 53 } //01 00  7u0BsdiaZb7IzC3y3ACfB98LKY8WezdmZcS
		$a_01_7 = {2e 72 65 41 64 74 6f 45 6e 64 } //00 00  .reAdtoEnd
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_DRR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DRR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 64 28 22 63 62 62 66 67 61 73 64 61 73 20 33 61 64 64 61 73 33 61 73 64 32 61 73 64 22 2c 20 32 30 2c 20 35 29 } //01 00  Mid("cbbfgasdas 3addas3asd2asd", 20, 5)
		$a_01_1 = {52 54 72 69 6d 28 72 75 62 65 6e 29 } //01 00  RTrim(ruben)
		$a_01_2 = {3a 5c 5c 4c 6f 61 65 6b 69 65 6a 61 61 73 6a 65 61 73 6a 74 68 65 6f 72 69 65 73 74 } //01 00  :\\Loaekiejaasjeasjtheoriest
		$a_01_3 = {53 74 72 69 6e 67 28 31 2c 20 22 68 22 29 20 2b 20 53 74 72 69 6e 67 28 32 2c 20 22 74 22 29 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 70 22 29 } //01 00  String(1, "h") + String(2, "t") + String(1, "p")
		$a_01_4 = {53 74 72 69 6e 67 28 31 2c 20 22 62 22 29 20 2b 20 72 75 62 65 6e 32 20 2b 20 22 74 22 20 2b 20 22 2e 22 20 2b 20 62 72 6f 6f 6d 73 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 79 22 29 20 2b 20 22 2f 22 20 26 20 69 64 20 2b 20 22 73 64 66 34 73 61 73 64 33 61 73 22 } //00 00  String(1, "b") + ruben2 + "t" + "." + brooms + String(1, "y") + "/" & id + "sdf4sasd3as"
	condition:
		any of ($a_*)
 
}