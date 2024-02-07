
rule TrojanDownloader_O97M_Qakbot_GRA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.GRA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 65 72 69 6b 76 61 6e 77 65 6c 2e 6e 6c 2f 78 79 71 66 6f 73 6e 6d 63 6d 71 2f } //01 00  http://erikvanwel.nl/xyqfosnmcmq/
		$a_01_1 = {43 3a 5c 47 72 61 76 69 74 79 5c 47 72 61 76 69 74 79 32 5c 46 69 6b 73 61 74 2e 65 78 65 } //01 00  C:\Gravity\Gravity2\Fiksat.exe
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}