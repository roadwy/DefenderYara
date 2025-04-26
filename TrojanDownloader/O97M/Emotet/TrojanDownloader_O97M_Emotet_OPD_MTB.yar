
rule TrojanDownloader_O97M_Emotet_OPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.OPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_01_0 = {69 71 72 61 61 63 66 69 6e 64 69 61 2e 6f 72 67 2f 77 70 2d 61 64 6d 69 6e 2f 64 47 2f } //1 iqraacfindia.org/wp-admin/dG/
		$a_01_1 = {68 65 2e 61 64 61 72 2d 61 6e 64 2d 69 64 6f 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 78 6b 37 44 2f } //1 he.adar-and-ido.com/wp-admin/xk7D/
		$a_01_2 = {77 22 26 22 77 77 2e 64 69 67 69 67 6f 61 6c 2e 66 72 2f 77 70 2d 61 64 6d 69 6e 2f 56 66 55 30 61 49 6a 2f } //1 w"&"ww.digigoal.fr/wp-admin/VfU0aIj/
		$a_01_3 = {63 61 72 7a 69 6e 6f 2e 61 74 77 65 62 70 61 67 65 73 2e 63 6f 6d 2f 61 73 73 65 74 73 2f 51 77 6c 68 78 68 73 59 66 6b 59 6e 74 4c 57 30 68 61 58 2f } //1 carzino.atwebpages.com/assets/QwlhxhsYfkYntLW0haX/
		$a_01_4 = {61 6c 2d 62 72 69 6b 2e 63 6f 6d 2f 76 62 2f 6d 4d 51 6c 62 48 50 43 58 2f } //1 al-brik.com/vb/mMQlbHPCX/
		$a_01_5 = {61 70 65 78 63 72 65 61 74 69 76 65 2e 63 6f 2e 6b 72 2f 61 64 6d 2f 56 64 69 4b 54 63 6c 6a 53 42 4f 52 51 52 72 73 68 36 36 58 2f } //1 apexcreative.co.kr/adm/VdiKTcljSBORQRrsh66X/
		$a_01_6 = {62 69 61 6e 74 61 72 61 6a 61 79 61 2e 63 6f 6d 2f 61 77 73 74 61 74 73 2d 69 63 6f 6e 2f 56 52 35 77 44 45 76 42 6a 2f } //1 biantarajaya.com/awstats-icon/VR5wDEvBj/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=1
 
}