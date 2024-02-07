
rule TrojanDownloader_O97M_Emotet_BOAI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BOAI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 62 6f 72 61 69 6e 74 65 72 63 61 6d 62 69 6f 73 2e 63 6f 6d 2e 62 72 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 41 4e 34 69 78 69 48 34 54 68 2f } //01 00  ://www.boraintercambios.com.br/wp-includes/AN4ixiH4Th/
		$a_01_1 = {3a 2f 2f 62 72 69 67 61 64 69 72 2e 63 6f 6d 2f 62 6b 70 2f 53 77 72 56 73 34 79 55 2f } //01 00  ://brigadir.com/bkp/SwrVs4yU/
		$a_01_2 = {3a 2f 2f 68 61 6e 64 62 6f 6f 67 36 2e 6e 6c 2f 4d 45 54 41 2d 49 4e 46 2f 66 2f } //01 00  ://handboog6.nl/META-INF/f/
		$a_01_3 = {3a 2f 2f 62 72 62 2d 6c 6a 75 62 75 73 6b 69 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 32 4d 4f 44 43 6b 30 55 5a 61 73 54 43 4c 36 74 6d 2f } //00 00  ://brb-ljubuski.com/wp-content/2MODCk0UZasTCL6tm/
	condition:
		any of ($a_*)
 
}