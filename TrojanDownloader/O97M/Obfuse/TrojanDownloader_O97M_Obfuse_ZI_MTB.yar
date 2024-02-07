
rule TrojanDownloader_O97M_Obfuse_ZI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ZI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 63 78 63 7a 78 63 22 } //01 00  Attribute VB_Name = "cxczxc"
		$a_01_1 = {46 75 6e 63 74 69 6f 6e 20 41 75 74 6f 5f 43 6c 6f 73 65 28 29 20 41 73 20 53 74 72 69 6e 67 } //01 00  Function Auto_Close() As String
		$a_03_2 = {53 68 65 6c 6c 20 63 61 6c 63 75 6c 61 74 6f 72 2e 90 02 14 2e 54 61 67 90 00 } //01 00 
		$a_01_3 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e } //00 00  End Function
	condition:
		any of ($a_*)
 
}