
rule TrojanDownloader_O97M_Powdow_ES_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ES!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 72 69 6c 61 65 72 2e 63 6f 6d 2f 49 66 41 6d 47 5a 49 4a 6a 62 77 7a 76 4b 4e 54 78 53 50 4d 2f 69 78 63 78 6d 7a 63 76 71 69 2e 65 78 65 } //1 http://rilaer.com/IfAmGZIJjbwzvKNTxSPM/ixcxmzcvqi.exe
		$a_01_1 = {43 3a 5c 6a 68 62 74 71 4e 6a 5c 49 4f 4b 56 59 6e 4a 5c 4b 55 64 59 43 52 6b 2e 65 78 65 } //1 C:\jhbtqNj\IOKVYnJ\KUdYCRk.exe
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}