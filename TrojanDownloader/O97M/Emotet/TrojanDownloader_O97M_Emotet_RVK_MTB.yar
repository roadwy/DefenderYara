
rule TrojanDownloader_O97M_Emotet_RVK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 09 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 66 61 6e 74 61 73 79 63 6c 75 62 2e 63 6f 6d 2e 62 72 2f 69 6d 67 73 2f 72 67 67 6d 56 54 66 76 54 2f } //1 www.fantasyclub.com.br/imgs/rggmVTfvT/
		$a_01_1 = {65 63 6f 61 72 63 68 2e 63 6f 6d 2e 74 77 2f 63 67 69 2d 62 69 6e 2f 76 57 57 2f } //1 ecoarch.com.tw/cgi-bin/vWW/
		$a_01_2 = {64 70 2d 66 6c 65 78 2e 63 6f 2e 6a 70 2f 63 67 69 2d 62 69 6e 2f 42 74 33 59 63 71 35 54 69 78 2f } //1 dp-flex.co.jp/cgi-bin/Bt3Ycq5Tix/
		$a_01_3 = {64 68 61 72 6d 61 63 6f 6d 75 6e 69 63 61 63 61 6f 2e 63 6f 6d 2e 62 72 2f 4f 4c 44 2f 50 6a 42 6b 56 42 68 55 48 2f } //1 dharmacomunicacao.com.br/OLD/PjBkVBhUH/
		$a_01_4 = {65 78 70 72 65 73 6f 63 62 61 2e 63 6f 6d 2e 61 72 2f 73 6e 6e 79 4e 6b 63 56 41 45 33 5a 74 69 74 77 2f 54 54 30 68 37 2f } //1 expresocba.com.ar/snnyNkcVAE3Ztitw/TT0h7/
		$a_01_5 = {6e 61 6e 64 6f 6e 69 6b 77 65 62 64 65 73 69 67 6e 2e 63 6f 6d 2f 4f 57 73 2f } //1 nandonikwebdesign.com/OWs/
		$a_01_6 = {67 65 6c 69 73 68 2e 63 6f 6d 2f 65 6d 61 69 6c 2d 68 6f 67 2f 59 58 61 50 69 57 62 46 4d 4b 54 2f } //1 gelish.com/email-hog/YXaPiWbFMKT/
		$a_01_7 = {6e 75 74 65 6e 73 70 6f 72 74 2d 77 65 7a 65 70 2e 6e 6c 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 51 79 65 7a 5a 6d 42 6d 54 4c 38 41 75 6c 4d 56 76 30 6f 68 2f } //1 nutensport-wezep.nl/wp-includes/QyezZmBmTL8AulMVv0oh/
		$a_01_8 = {6f 6d 65 72 79 65 6e 65 72 2e 63 6f 6d 2e 74 72 2f 77 70 2d 61 64 6d 69 6e 2f 6f 61 6b 77 63 6f 57 75 66 69 69 30 4a 52 38 39 47 2f } //1 omeryener.com.tr/wp-admin/oakwcoWufii0JR89G/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=1
 
}