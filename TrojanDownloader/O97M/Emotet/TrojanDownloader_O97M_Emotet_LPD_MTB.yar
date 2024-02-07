
rule TrojanDownloader_O97M_Emotet_LPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.LPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 63 61 6e 69 73 6d 61 6c 6c 6f 72 63 61 2e 65 73 2f 77 70 2d 61 64 6d 69 6e 2f 4f 54 79 65 59 72 78 39 43 39 42 76 59 76 56 62 33 2f } //01 00  ://canismallorca.es/wp-admin/OTyeYrx9C9BvYvVb3/
		$a_01_1 = {3a 2f 2f 63 61 70 73 6c 6f 63 6b 2e 63 6f 2e 7a 61 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 4c 4d 6e 67 55 55 54 75 61 6e 42 6f 66 72 35 7a 4b 2f } //01 00  ://capslock.co.za/wp-includes/LMngUUTuanBofr5zK/
		$a_01_2 = {3a 2f 2f 77 77 77 2e 63 61 66 65 2d 6b 77 65 62 62 65 6c 2e 6e 6c 2f 6c 61 79 6f 75 74 73 2f 33 57 6b 65 76 2f } //01 00  ://www.cafe-kwebbel.nl/layouts/3Wkev/
		$a_01_3 = {3a 2f 2f 62 6b 70 73 2e 61 63 2e 74 68 2f 62 39 31 2d 73 74 64 36 33 2f 49 78 76 35 32 6d 38 67 75 34 61 61 55 69 79 62 2f } //01 00  ://bkps.ac.th/b91-std63/Ixv52m8gu4aaUiyb/
		$a_01_4 = {3a 2f 2f 62 6f 72 62 61 6a 61 72 64 69 6e 61 67 65 6d 2e 63 6f 6d 2e 62 72 2f 65 72 72 6f 73 2f 76 6c 42 33 66 36 58 70 73 5a 47 2f } //01 00  ://borbajardinagem.com.br/erros/vlB3f6XpsZG/
		$a_01_5 = {3a 2f 2f 77 77 77 2e 62 65 73 74 2d 64 65 73 69 67 6e 2e 67 72 2f 5f 65 72 72 6f 72 70 61 67 65 73 2f 39 77 43 61 37 47 4c 49 30 63 6c 36 6e 4d 2f } //01 00  ://www.best-design.gr/_errorpages/9wCa7GLI0cl6nM/
		$a_01_6 = {3a 2f 2f 62 65 6c 6c 65 69 6c 65 2d 64 6f 2e 66 72 2f 64 69 61 70 6f 2d 69 6c 65 2f 45 65 42 48 79 66 47 6f 4b 59 41 43 59 2f } //00 00  ://belleile-do.fr/diapo-ile/EeBHyfGoKYACY/
	condition:
		any of ($a_*)
 
}