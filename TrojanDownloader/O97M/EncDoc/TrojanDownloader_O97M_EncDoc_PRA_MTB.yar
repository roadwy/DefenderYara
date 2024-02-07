
rule TrojanDownloader_O97M_EncDoc_PRA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PRA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f 36 38 2e 31 38 33 2e 36 37 2e 31 39 38 2f 76 6b 69 2e 65 78 65 22 20 27 57 68 65 72 65 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 74 68 65 20 66 69 6c 65 20 66 72 6f 6d } //01 00  URL = "http://68.183.67.198/vki.exe" 'Where to download the file from
		$a_01_1 = {73 74 72 65 61 6d 5f 6f 62 6a 2e 73 61 76 65 74 6f 66 69 6c 65 20 46 69 6c 65 4e 61 6d 65 2c 20 32 } //00 00  stream_obj.savetofile FileName, 2
	condition:
		any of ($a_*)
 
}