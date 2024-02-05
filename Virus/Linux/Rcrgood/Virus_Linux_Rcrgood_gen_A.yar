
rule Virus_Linux_Rcrgood_gen_A{
	meta:
		description = "Virus:Linux/Rcrgood.gen!A,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {81 29 7f 45 4c 46 75 64 80 69 10 02 75 5e 83 c1 20 ff 49 14 75 f8 8b 41 28 f7 d8 80 e4 0f 66 3d } //01 00 
		$a_00_1 = {81 29 7f 45 4c 46 75 69 80 69 10 02 75 63 81 c1 20 00 00 00 ff 49 14 75 f5 8b 41 28 f7 d8 80 e4 0f 66 3d } //01 00 
		$a_00_2 = {5b 34 30 39 36 5d 20 76 69 72 75 73 20 63 6f 64 65 64 20 62 79 20 62 61 64 43 52 43 20 69 6e 20 32 30 30 33 } //00 00 
	condition:
		any of ($a_*)
 
}