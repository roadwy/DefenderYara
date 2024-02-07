
rule TrojanDownloader_O97M_Powdow_EQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.EQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 75 72 65 66 65 72 65 2e 6f 72 67 2f 6f 70 78 65 2e 65 78 65 } //01 00  http://urefere.org/opxe.exe
		$a_01_1 = {43 3a 5c 49 46 79 52 4f 6c 48 5c 66 6c 68 74 77 4c 67 5c 69 72 43 77 61 70 49 2e 65 78 } //01 00  C:\IFyROlH\flhtwLg\irCwapI.ex
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}