
rule TrojanDownloader_O97M_Adnel_D{
	meta:
		description = "TrojanDownloader:O97M/Adnel.D,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {2b 20 22 6c 69 63 61 74 69 6f 6e 22 29 0d 0a 6f 49 55 49 59 67 73 61 64 66 64 73 76 64 76 73 2e 4f 70 65 6e 20 45 6e 76 69 72 6f 6e 28 22 54 45 22 20 2b 20 22 4d 50 22 29 20 26 20 22 5c 64 73 66 66 66 66 64 2e 76 62 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Adnel_D_2{
	meta:
		description = "TrojanDownloader:O97M/Adnel.D,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 75 72 79 79 2e 4e 63 63 79 76 70 6e 67 76 62 61 } //01 00  Furyy.Nccyvpngvba
		$a_01_1 = {4e 51 42 51 4f 2e 46 67 65 72 6e 7a } //01 00  NQBQO.Fgernz
		$a_01_2 = {46 70 65 76 63 67 76 61 74 2e 53 76 79 72 46 6c 66 67 72 7a 42 6f 77 72 70 67 } //01 00  Fpevcgvat.SvyrFlfgrzBowrpg
		$a_01_3 = {5a 46 4b 5a 59 32 2e 4b 5a 59 55 47 47 43 } //00 00  ZFKZY2.KZYUGGC
	condition:
		any of ($a_*)
 
}