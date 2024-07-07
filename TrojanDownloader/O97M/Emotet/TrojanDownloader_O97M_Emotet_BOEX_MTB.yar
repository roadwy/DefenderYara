
rule TrojanDownloader_O97M_Emotet_BOEX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BOEX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 0a 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 70 72 65 66 65 72 72 65 64 73 75 70 70 6f 72 74 73 2e 63 6f 6d 2f 63 6c 69 2f 72 4b 39 73 47 32 2f } //1 ://www.preferredsupports.com/cli/rK9sG2/
		$a_01_1 = {3a 2f 2f 68 6f 6d 64 65 63 6f 72 73 74 61 74 69 6f 6e 2e 63 6f 6d 2f 77 61 7a 66 37 6a 2f 74 50 34 50 48 2f } //1 ://homdecorstation.com/wazf7j/tP4PH/
		$a_01_2 = {3a 2f 2f 73 61 76 61 67 65 72 65 66 69 6e 69 73 68 65 20 72 69 6e 63 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 4e 79 31 2f } //1 ://savagerefinishe rinc.com/cgi-bin/Ny1/
		$a_01_3 = {3a 2f 2f 68 61 71 73 6f 6e 73 67 72 6f 75 70 2e 63 6f 6d 2f 63 73 73 2f 4c 42 48 52 49 75 2f } //1 ://haqsonsgroup.com/css/LBHRIu/
		$a_01_4 = {3a 2f 2f 6c 61 75 72 61 6d 61 72 73 68 61 6c 6c 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 73 78 53 38 63 74 62 6c 72 2f } //1 ://lauramarshall.com/cgi-bin/sxS8ctblr/
		$a_01_5 = {3a 2f 2f 62 75 72 69 61 6c 69 6e 73 75 72 61 6e 63 65 6c 61 62 2e 63 6f 6d 2f 71 35 6b 6a 65 39 2f 4b 31 6d 46 2f } //1 ://burialinsurancelab.com/q5kje9/K1mF/
		$a_01_6 = {3a 2f 2f 6c 65 61 6c 72 61 63 65 63 61 72 73 2e 63 6f 6d 2f 64 6f 6e 6e 61 63 6f 78 2f 66 56 71 4f 59 42 7a 41 55 6f 55 2f } //1 ://lealracecars.com/donnacox/fVqOYBzAUoU/
		$a_01_7 = {3a 2f 2f 65 64 67 65 74 61 63 74 69 63 61 6c 2e 72 69 74 61 62 69 6c 69 73 69 6d 2e 63 6f 6d 2f 61 64 6d 69 6e 2f 32 6a 4b 42 45 47 44 59 30 58 70 63 67 78 46 37 66 2f } //1 ://edgetactical.ritabilisim.com/admin/2jKBEGDY0XpcgxF7f/
		$a_01_8 = {3a 2f 2f 34 73 65 61 73 6f 6e 73 66 6c 6f 72 61 6c 73 2e 63 6f 6d 2f 79 68 65 64 6a 6b 6c 2f 42 59 77 79 58 6f 72 71 44 79 77 78 2f } //1 ://4seasonsflorals.com/yhedjkl/BYwyXorqDywx/
		$a_01_9 = {3a 2f 2f 62 6f 6c 64 63 6f 6e 73 75 6c 74 69 6e 67 2e 69 6e 66 6f 2f 62 6b 7a 68 36 76 2f 65 71 62 41 67 63 33 6f 4d 47 42 73 43 35 56 44 6e 31 77 2f } //1 ://boldconsulting.info/bkzh6v/eqbAgc3oMGBsC5VDn1w/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=1
 
}