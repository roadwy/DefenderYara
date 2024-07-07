
rule TrojanDownloader_O97M_Emotet_AUPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AUPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6f 70 65 6e 63 61 72 74 2d 64 65 73 74 65 6b 2e 63 6f 6d 2f 63 61 74 61 6c 6f 67 2f 49 37 62 42 74 4b 54 33 66 32 68 70 6d 68 72 56 2f } //1 ://opencart-destek.com/catalog/I7bBtKT3f2hpmhrV/
		$a_01_1 = {3a 2f 2f 76 6f 69 64 2e 62 79 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 5a 2f } //1 ://void.by/wp-content/Z/
		$a_01_2 = {3a 2f 2f 6f 6e 63 72 65 74 65 2d 65 67 79 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 47 36 6c 39 7a 43 73 42 2f } //1 ://oncrete-egy.com/wp-content/G6l9zCsB/
		$a_01_3 = {3a 2f 2f 77 77 77 2e 6e 65 6b 72 65 74 6e 69 6e 65 2d 61 72 6b 61 2e 68 72 2f 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 2f 58 53 39 75 75 61 6d 2f } //1 ://www.nekretnine-arka.hr/administrator/XS9uuam/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}