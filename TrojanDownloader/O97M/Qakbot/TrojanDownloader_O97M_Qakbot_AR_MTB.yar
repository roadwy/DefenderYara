
rule TrojanDownloader_O97M_Qakbot_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,1e 00 1e 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {31 32 35 34 37 35 30 2e 70 6e 67 } //0a 00  1254750.png
		$a_01_1 = {43 3a 5c 54 65 73 74 5c 74 65 73 74 32 5c 46 69 6b 73 61 74 2e 65 78 65 } //01 00  C:\Test\test2\Fiksat.exe
		$a_01_2 = {4f 70 65 6e 55 52 4c } //0a 00  OpenURL
		$a_01_3 = {68 74 74 70 3a 2f 2f 64 69 6d 61 73 2e 73 74 69 66 61 72 2e 61 63 2e 69 64 2f 76 6a 72 7a 7a 75 66 73 75 2f } //00 00  http://dimas.stifar.ac.id/vjrzzufsu/
		$a_00_4 = {8f 7e 00 00 0c 00 0c 00 05 00 00 01 00 12 01 55 52 4c 44 6f 77 } //6e 6c 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_AR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_01_1 = {43 3a 5c 43 4f 73 75 76 5c 57 65 67 65 72 62 5c 73 7a 76 4d 68 65 67 6e 2e 65 78 65 } //01 00  C:\COsuv\Wegerb\szvMhegn.exe
		$a_01_2 = {55 52 4c 4d 6f 6e } //01 00  URLMon
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //0a 00  ShellExecuteA
		$a_01_4 = {68 74 74 70 3a 2f 2f 74 61 6b 2d 74 69 6b 2e 73 69 74 65 2f 63 72 75 6e 32 30 2e 67 69 66 } //00 00  http://tak-tik.site/crun20.gif
		$a_00_5 = {8f 9d 00 00 14 00 14 00 04 00 } //00 0a 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_AR_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,14 00 14 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 49 6f 70 73 64 5c } //14 00  C:\Iopsd\
		$a_00_1 = {68 74 74 70 3a 2f 2f 74 72 61 64 75 63 65 72 65 6a 75 72 69 64 69 63 61 2e 72 6f 2f 74 65 6e 6c 78 68 6c 7a 70 61 67 63 2f 44 } //14 00  http://traducerejuridica.ro/tenlxhlzpagc/D
		$a_00_2 = {68 74 74 70 3a 2f 2f 74 72 61 64 75 63 65 72 65 6a 75 72 69 64 69 63 61 2e 72 6f 2f 74 65 6e 6c 78 68 6c 7a 70 61 67 63 2f 36 32 35 39 38 36 2e 70 6e 67 } //0a 00  http://traducerejuridica.ro/tenlxhlzpagc/625986.png
		$a_00_3 = {65 78 65 07 00 00 7a 69 70 66 6c 64 72 03 00 00 4d 6f 6e 06 00 00 4a 4a 43 43 43 4a } //00 00 
		$a_00_4 = {e7 2b 00 00 00 00 27 00 c7 05 } //93 67 
	condition:
		any of ($a_*)
 
}