
rule TrojanDownloader_O97M_Emotet_ALV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ALV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 70 64 2e 63 6c 2f 63 67 69 2d 62 69 6e 2f 38 33 45 30 78 67 54 4d 63 2f } //1 fpd.cl/cgi-bin/83E0xgTMc/
		$a_01_1 = {65 6c 2d 65 6e 65 72 67 69 61 6b 69 2e 67 72 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 72 65 61 6c 6c 79 2d 73 69 6d 70 6c 65 2d 73 73 6c 2f 74 65 73 74 73 73 6c 2f 73 65 72 76 65 72 70 6f 72 74 34 34 33 2f 57 55 56 35 50 4a 41 2f } //1 el-energiaki.gr/wp-content/plugins/really-simple-ssl/testssl/serverport443/WUV5PJA/
		$a_01_2 = {77 77 77 2e 6d 61 6e 63 68 65 73 74 65 72 73 6c 74 2e 63 6f 2e 75 6b 2f 61 2d 74 6f 2d 7a 2d 6f 66 2d 73 6c 74 2f 4e 74 72 63 69 33 52 79 2f } //1 www.manchesterslt.co.uk/a-to-z-of-slt/Ntrci3Ry/
		$a_01_3 = {63 6f 6e 74 61 63 74 77 6f 72 6b 73 2e 6e 6c 2f 6c 61 79 6f 75 74 73 2f 66 46 78 4b 5a 61 62 68 2f } //1 contactworks.nl/layouts/fFxKZabh/
		$a_01_4 = {62 61 79 6b 75 73 6f 67 6c 75 2e 63 6f 6d 2e 74 72 2f 77 70 2d 61 64 6d 69 6e 2f 59 33 73 52 42 63 4f 66 5a 33 34 77 67 32 73 4f 2f } //1 baykusoglu.com.tr/wp-admin/Y3sRBcOfZ34wg2sO/
		$a_01_5 = {63 65 69 62 61 64 69 73 65 6e 6f 2e 63 6f 6d 2e 6d 78 2f 62 72 6f 63 68 75 72 65 2f 6b 42 75 4e 6a 73 45 43 53 39 79 32 67 52 42 36 78 61 43 2f } //1 ceibadiseno.com.mx/brochure/kBuNjsECS9y2gRB6xaC/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}