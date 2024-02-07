
rule TrojanDownloader_O97M_EncDoc_YAJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.YAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 6d 75 65 62 6c 65 73 6d 61 70 6c 65 2e 63 6f 6d 2e 6d 78 2f 31 39 2e 67 69 66 } //01 00  https://mueblesmaple.com.mx/19.gif
		$a_01_1 = {43 3a 5c 57 45 72 74 75 5c 52 65 74 65 72 64 5c 73 7a 76 6d 68 65 67 75 2e 65 78 65 } //00 00  C:\WErtu\Reterd\szvmhegu.exe
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_YAJ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.YAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 70 70 61 6e 6f 6e 6c 69 6e 65 2e 69 6e 2f 73 61 68 78 69 66 77 6f 6d 63 7a 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } //01 00  appanonline.in/sahxifwomcz/555555555.png
		$a_00_1 = {43 3a 5c 46 65 74 69 6c 5c 47 69 6f 6c 61 5c 6f 63 65 61 6e 44 68 } //01 00  C:\Fetil\Giola\oceanDh
		$a_01_2 = {6c 65 79 64 65 72 6f 6d 70 69 65 6e 74 65 73 2e 63 6c 2f 79 77 68 62 6e 69 7a 79 6c 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } //00 00  leyderompientes.cl/ywhbnizyl/555555555.png
	condition:
		any of ($a_*)
 
}