
rule TrojanDownloader_O97M_Emotet_GGPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.GGPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 63 61 73 61 63 68 65 2e 63 6f 6d 2f 77 65 62 2f 6e 33 6a 78 77 58 58 77 61 2f } //1 ://casache.com/web/n3jxwXXwa/
		$a_01_1 = {3a 2f 2f 77 77 77 2e 62 6c 65 73 73 69 6e 67 73 6f 75 72 63 65 2e 63 6f 6d 2f 62 6c 65 73 73 69 6e 67 73 6f 75 72 63 65 2e 63 6f 6d 2f 72 46 51 30 49 70 36 6c 51 58 58 4b 2f } //1 ://www.blessingsource.com/blessingsource.com/rFQ0Ip6lQXXK/
		$a_01_2 = {3a 2f 2f 63 63 61 6c 61 69 72 65 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 64 31 70 47 52 61 30 58 2f } //1 ://ccalaire.com/wp-admin/d1pGRa0X/
		$a_01_3 = {3a 2f 2f 63 64 69 6d 70 72 69 6e 74 70 72 2e 63 6f 6d 2f 62 72 6f 63 68 75 72 65 32 2f 41 39 4e 6d 59 44 6e 64 5a 2f } //1 ://cdimprintpr.com/brochure2/A9NmYDndZ/
		$a_01_4 = {3a 2f 2f 63 61 72 65 65 72 70 6c 61 6e 2e 68 6f 73 74 32 30 2e 75 6b 2f 69 6d 61 67 65 73 2f 4c 73 2f } //1 ://careerplan.host20.uk/images/Ls/
		$a_01_5 = {3a 2f 2f 61 75 73 6e 7a 2e 6e 65 74 2f 32 30 31 30 77 63 2f 6f 64 53 69 35 74 51 4b 6b 43 49 58 45 57 6c 39 2f } //1 ://ausnz.net/2010wc/odSi5tQKkCIXEWl9/
		$a_01_6 = {3a 2f 2f 61 7a 73 69 61 63 65 6e 74 65 72 2e 63 6f 6d 2f 6a 73 2f 73 4f 68 6d 69 6f 73 4c 4a 4f 67 77 61 50 36 69 35 6e 6c 6e 2f } //1 ://azsiacenter.com/js/sOhmiosLJOgwaP6i5nln/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=1
 
}