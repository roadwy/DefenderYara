
rule TrojanDownloader_O97M_Emotet_NPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.NPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 75 73 6e 7a 2e 6e 65 74 2f 32 30 31 30 77 63 2f 52 68 41 59 56 50 4e 79 70 6a 70 68 4e 4e 6b 36 4a 2f } //1 ausnz.net/2010wc/RhAYVPNypjphNNk6J/
		$a_01_1 = {62 65 6c 69 73 69 70 2e 6e 65 74 2f 6c 69 62 73 2f 53 77 69 66 74 2d 35 2e 31 2e 30 2f 46 35 58 55 37 45 75 50 65 50 51 2f } //1 belisip.net/libs/Swift-5.1.0/F5XU7EuPePQ/
		$a_01_2 = {62 6c 6f 67 2e 63 65 6e 74 65 72 6b 69 6e 67 2e 74 6f 70 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 57 45 49 75 50 61 66 7a 30 62 53 2f } //1 blog.centerking.top/wp-includes/WEIuPafz0bS/
		$a_01_3 = {65 64 75 2d 6d 65 64 69 61 2e 63 6e 2f 77 70 2d 61 64 6d 69 6e 2f 54 4f 75 2f } //1 edu-media.cn/wp-admin/TOu/
		$a_01_4 = {70 70 69 61 62 61 6e 79 75 77 61 6e 67 69 2e 6f 72 2e 69 64 2f 6c 75 6c 75 2d 31 39 33 37 2f 64 61 55 52 44 4e 55 79 73 6f 2f } //1 ppiabanyuwangi.or.id/lulu-1937/daURDNUyso/
		$a_01_5 = {6c 79 64 74 2e 63 63 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 6a 70 72 70 63 4f 38 55 2f } //1 lydt.cc/wp-includes/jprpcO8U/
		$a_01_6 = {61 63 65 72 65 73 74 6f 72 61 74 69 6f 6e 2e 63 6f 2e 7a 61 2f 77 70 2d 61 64 6d 69 6e 2f 67 4a 71 4d 42 59 68 51 48 59 73 44 45 2f } //1 acerestoration.co.za/wp-admin/gJqMBYhQHYsDE/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=1
 
}