
rule TrojanDownloader_O97M_Emotet_RVT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 77 77 77 2e 61 74 68 61 6e 6c 69 66 65 61 70 69 2e 63 6f 6d 2e 61 72 2f 41 72 63 68 69 76 6f 73 2f 55 48 6a 58 51 4d 36 4c 32 33 4e 2f 22 2c 22 } //1 //www.athanlifeapi.com.ar/Archivos/UHjXQM6L23N/","
		$a_01_1 = {2f 2f 62 72 65 61 6b 64 6f 77 6e 6c 61 6e 65 6d 6f 76 69 65 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 5a 4d 55 34 61 53 61 59 6c 65 53 2f 22 2c 22 } //1 //breakdownlanemovie.com/wp-admin/ZMU4aSaYleS/","
		$a_01_2 = {2f 2f 63 68 61 6c 65 64 6f 6f 6c 65 6f 2e 63 6f 6d 2e 62 72 2f 68 65 61 64 65 72 73 2f 6e 77 51 4e 43 75 78 4b 30 6b 35 4f 77 79 58 53 50 79 50 2f 22 2c 22 } //1 //chaledooleo.com.br/headers/nwQNCuxK0k5OwyXSPyP/","
		$a_01_3 = {2f 2f 63 61 6e 6e 69 70 69 75 73 2e 6e 6c 2f 63 67 69 2d 62 69 6e 2f 54 67 50 41 2f 22 2c 22 } //1 //cannipius.nl/cgi-bin/TgPA/","
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}