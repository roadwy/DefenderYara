
rule TrojanDownloader_O97M_Obfuse_KE{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KE,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {20 3d 20 52 69 67 68 74 24 28 4d 69 64 24 28 4d 69 64 24 28 4d 69 64 24 28 52 69 67 68 74 24 28 4c 65 66 74 24 28 4c 65 66 74 24 28 } //0a 00   = Right$(Mid$(Mid$(Mid$(Right$(Left$(Left$(
		$a_01_1 = {20 3d 20 45 6e 76 69 72 6f 6e 24 28 53 74 72 52 65 76 65 72 73 65 28 6d 6c 77 28 } //00 00   = Environ$(StrReverse(mlw(
	condition:
		any of ($a_*)
 
}