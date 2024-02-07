
rule TrojanDownloader_O97M_Emotet_PDU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 65 64 69 63 61 74 69 65 66 61 72 61 68 6f 74 61 72 65 2e 72 6f 79 61 6c 77 65 62 68 6f 73 74 69 6e 67 2e 6e 65 74 2f 38 51 33 33 4f 38 76 36 33 45 69 32 68 32 67 2f } //01 00  ://edicatiefarahotare.royalwebhosting.net/8Q33O8v63Ei2h2g/
		$a_01_1 = {3a 2f 2f 65 73 74 65 74 61 61 61 61 61 2e 31 32 35 6d 62 2e 63 6f 6d 2f 61 64 6d 69 6e 2f 49 45 35 7a 75 35 41 39 6c 79 2f } //01 00  ://estetaaaaa.125mb.com/admin/IE5zu5A9ly/
		$a_01_2 = {3a 2f 2f 66 61 73 6f 76 69 74 72 69 6e 65 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 35 45 68 50 4a 31 34 74 4f 53 7a 54 2f } //01 00  ://fasovitrine.com/wp-admin/5EhPJ14tOSzT/
		$a_01_3 = {3a 2f 2f 67 61 64 64 63 6f 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 73 41 52 61 33 39 64 75 65 2f } //01 00  ://gaddco.com/cgi-bin/sARa39due/
		$a_01_4 = {3a 2f 2f 77 77 77 2e 68 69 68 37 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 45 51 5a 59 54 2f } //01 00  ://www.hih7.com/wp-admin/EQZYT/
		$a_01_5 = {3a 2f 2f 77 77 77 2e 79 65 73 64 65 6b 6f 2e 63 6f 6d 2f 62 65 2f 36 79 68 4f 66 71 4c 48 32 4e 4d 56 74 55 51 75 50 59 44 2f } //01 00  ://www.yesdeko.com/be/6yhOfqLH2NMVtUQuPYD/
		$a_01_6 = {3a 2f 2f 6a 6f 6e 61 6c 6f 72 65 64 6f 2e 63 6f 6d 2f 69 6e 63 2f 47 36 6d 72 31 55 35 72 66 44 37 58 65 58 2f } //00 00  ://jonaloredo.com/inc/G6mr1U5rfD7XeX/
	condition:
		any of ($a_*)
 
}