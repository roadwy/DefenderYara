
rule TrojanDownloader_O97M_RevengeRAT_RPI_MTB{
	meta:
		description = "TrojanDownloader:O97M/RevengeRAT.RPI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 73 68 61 72 65 2e 7a 69 67 68 74 2e 63 6f 6d 2f 76 31 75 6e 7a 6e 65 64 2f 64 6f 77 6e 6c 6f 61 64 2f 75 70 64 61 74 65 2e 76 62 73 3f 75 74 6d 5f 73 6f 75 72 63 65 3d 76 69 65 77 65 72 } //1 https://share.zight.com/v1unzned/download/update.vbs?utm_source=viewer
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 34 73 79 6e 63 2e 63 6f 6d 2f 77 65 62 2f 64 69 72 65 63 74 44 6f 77 6e 6c 6f 61 64 2f 57 74 5a 62 4b 61 45 6c 2f 34 50 47 79 47 34 69 64 2e 39 63 34 62 37 62 35 34 61 30 37 62 39 32 63 38 36 32 65 38 31 39 33 35 65 30 66 64 61 39 37 34 } //1 https://www.4sync.com/web/directDownload/WtZbKaEl/4PGyG4id.9c4b7b54a07b92c862e81935e0fda974
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}