
rule TrojanDownloader_O97M_EncDoc_RVB_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RVB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 62 65 61 72 74 6f 6f 74 68 6b 61 77 61 73 61 6b 69 2e 63 6f 6d 2f 51 4a 54 31 39 6a 68 74 77 48 74 2f 67 67 2e 68 74 6d 6c } //01 00  https://beartoothkawasaki.com/QJT19jhtwHt/gg.html
		$a_01_1 = {5c 63 65 78 79 7a 32 2e 64 6c 6c } //01 00  \cexyz2.dll
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}