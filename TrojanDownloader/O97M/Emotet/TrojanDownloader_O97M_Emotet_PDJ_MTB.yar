
rule TrojanDownloader_O97M_Emotet_PDJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 70 69 61 6a 69 6d 65 6e 65 7a 2e 63 6f 6d 2f 46 6f 78 2d 43 2f 64 53 34 6e 76 33 73 70 59 64 30 44 5a 73 6e 77 4c 71 6f 76 2f } //01 00  ://piajimenez.com/Fox-C/dS4nv3spYd0DZsnwLqov/
		$a_01_1 = {3a 2f 2f 69 6e 6f 70 72 61 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 33 7a 47 6e 51 47 4e 43 76 49 4b 75 76 72 4f 37 54 2f } //01 00  ://inopra.com/wp-includes/3zGnQGNCvIKuvrO7T/
		$a_01_2 = {3a 2f 2f 62 69 6f 6d 65 64 69 63 61 6c 70 68 61 72 6d 61 65 67 79 70 74 2e 63 6f 6d 2f 73 61 70 62 75 73 68 2f 42 4b 45 61 56 71 31 7a 6f 79 4a 73 73 6d 55 6f 65 2f } //01 00  ://biomedicalpharmaegypt.com/sapbush/BKEaVq1zoyJssmUoe/
		$a_01_3 = {3a 2f 2f 67 65 74 6c 69 76 65 74 65 78 74 2e 63 6f 6d 2f 50 65 63 74 69 6e 61 63 65 61 2f 41 4c 35 46 56 70 6a 6c 65 43 57 2f } //01 00  ://getlivetext.com/Pectinacea/AL5FVpjleCW/
		$a_01_4 = {3a 2f 2f 6a 61 6e 73 68 61 62 64 2e 63 6f 6d 2f 5a 67 79 65 32 2f } //01 00  ://janshabd.com/Zgye2/
		$a_01_5 = {3a 2f 2f 6a 75 73 74 66 6f 72 61 6e 69 6d 65 2e 63 6f 6d 2f 73 74 72 61 74 6f 73 65 2f 50 6f 6e 77 50 58 43 6c 2f } //00 00  ://justforanime.com/stratose/PonwPXCl/
	condition:
		any of ($a_*)
 
}