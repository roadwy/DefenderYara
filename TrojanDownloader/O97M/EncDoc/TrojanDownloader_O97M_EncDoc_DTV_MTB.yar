
rule TrojanDownloader_O97M_EncDoc_DTV_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.DTV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 6b 65 6e 6e 65 74 68 66 61 6e 74 65 73 2e 63 6f 6d 2f 76 65 2f 71 61 73 2e 45 58 45 } //01 00  https://kennethfantes.com/ve/qas.EXE
		$a_01_1 = {43 3a 5c 45 53 4f 77 4c 6b 6b 5c 4c 55 67 4a 63 49 66 5c 70 68 53 7a 43 58 7a 2e 65 78 65 } //01 00  C:\ESOwLkk\LUgJcIf\phSzCXz.exe
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}