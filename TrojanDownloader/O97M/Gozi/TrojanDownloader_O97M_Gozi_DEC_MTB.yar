
rule TrojanDownloader_O97M_Gozi_DEC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.DEC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 67 65 6e 74 73 79 73 74 65 6d 73 2e 62 61 72 2f 6f 70 7a 69 6f 6e 61 6c 6c 61 2e 64 6c 6c } //1 http://agentsystems.bar/opzionalla.dll
		$a_01_1 = {43 3a 5c 47 6d 48 4d 55 4b 70 5c 79 7a 78 44 61 67 6e } //1 C:\GmHMUKp\yzxDagn
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Gozi_DEC_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Gozi.DEC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 67 65 6e 74 73 79 73 74 65 6d 73 2e 63 79 6f 75 2f 6f 70 7a 69 6f 6e 61 6c 6c 61 2e 64 6c 6c } //1 http://agentsystems.cyou/opzionalla.dll
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {43 3a 5c 44 53 4c 75 63 66 7a 5c 63 67 75 72 61 6e 4e } //1 C:\DSLucfz\cguranN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}