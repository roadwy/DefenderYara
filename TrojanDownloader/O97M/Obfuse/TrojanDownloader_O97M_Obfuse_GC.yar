
rule TrojanDownloader_O97M_Obfuse_GC{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GC,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //02 00  Sub AutoOpen()
		$a_03_1 = {2e 52 75 6e 40 20 90 02 12 20 5f 90 00 } //01 00 
		$a_01_2 = {3d 20 56 42 41 2e 20 5f } //01 00  = VBA. _
		$a_03_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 12 2e 54 65 78 74 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}