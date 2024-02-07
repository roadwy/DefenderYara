
rule TrojanDownloader_O97M_Emotet_PDO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6d 6f 76 65 63 6f 6e 6e 65 63 74 73 2e 63 6f 6d 2f 6e 76 63 6c 6c 65 37 79 2f 70 44 31 76 4d 4d 46 52 4b 53 39 77 61 73 41 34 45 2f } //01 00  ://moveconnects.com/nvclle7y/pD1vMMFRKS9wasA4E/
		$a_01_1 = {3a 2f 2f 74 6f 74 61 6c 70 6c 61 79 74 75 78 74 6c 61 2e 63 6f 6d 2f 73 69 74 69 6f 2f 74 45 4d 4f 77 57 52 68 2f } //01 00  ://totalplaytuxtla.com/sitio/tEMOwWRh/
		$a_01_2 = {3a 2f 2f 6d 65 63 61 2d 67 6c 6f 62 61 6c 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 7a 70 4d 36 4c 38 4b 58 59 30 48 2f } //01 00  ://meca-global.com/wp-admin/zpM6L8KXY0H/
		$a_01_3 = {3a 2f 2f 79 64 78 69 6e 7a 75 6f 2e 63 6e 2f 30 67 66 77 6a 67 68 2f 31 73 6f 64 62 55 45 7a 59 7a 54 52 79 79 2f } //01 00  ://ydxinzuo.cn/0gfwjgh/1sodbUEzYzTRyy/
		$a_01_4 = {3a 2f 2f 35 31 2e 32 32 32 2e 37 32 2e 32 33 32 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 33 7a 74 71 63 74 63 59 72 2f } //01 00  ://51.222.72.232/wp-includes/3ztqctcYr/
		$a_01_5 = {3a 2f 2f 35 31 2e 32 32 32 2e 37 32 2e 32 33 33 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 58 69 36 30 51 58 39 6b 68 65 2f } //00 00  ://51.222.72.233/wp-includes/Xi60QX9khe/
	condition:
		any of ($a_*)
 
}