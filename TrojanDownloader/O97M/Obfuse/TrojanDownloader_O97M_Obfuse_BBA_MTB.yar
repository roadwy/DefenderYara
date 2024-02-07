
rule TrojanDownloader_O97M_Obfuse_BBA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BBA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 67 74 2e 49 6e 73 74 61 6c 6c 50 72 6f 64 75 63 74 20 22 68 74 74 70 73 3a 2f 2f 63 76 67 2e 6f 72 67 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 32 30 32 30 2f 64 6f 63 75 6d 65 6e 74 2e 7a 69 70 } //00 00  dgt.InstallProduct "https://cvg.org/wp-content/uploads/2020/document.zip
	condition:
		any of ($a_*)
 
}