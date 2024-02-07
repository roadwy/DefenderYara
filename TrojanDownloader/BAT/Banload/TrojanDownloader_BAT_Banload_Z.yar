
rule TrojanDownloader_BAT_Banload_Z{
	meta:
		description = "TrojanDownloader:BAT/Banload.Z,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 90 02 10 2e 00 7a 00 69 00 70 00 00 90 00 } //01 00 
		$a_03_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 90 02 10 2e 00 63 00 70 00 6c 00 00 90 00 } //01 00 
		$a_03_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 37 00 39 00 2e 00 31 00 38 00 38 00 2e 00 33 00 38 00 2e 00 34 00 32 00 2f 00 90 02 15 2e 00 7a 00 69 00 70 00 00 90 00 } //02 00 
		$a_01_3 = {44 3a 5c 52 4f 44 41 4e 44 4f 5c 50 52 4f 4a 45 54 4f 20 50 47 20 53 55 42 5a 49 44 5c 4d 6f 64 20 4c 6f 61 64 65 72 73 5c 45 78 65 6d 70 6c 6f 20 44 6f 69 73 20 32 5c 6f 62 6a 5c 44 65 62 75 67 5c 6a 32 5f 32 2e 70 64 62 } //00 00  D:\RODANDO\PROJETO PG SUBZID\Mod Loaders\Exemplo Dois 2\obj\Debug\j2_2.pdb
		$a_00_4 = {5d 04 00 } //00 cc 
	condition:
		any of ($a_*)
 
}