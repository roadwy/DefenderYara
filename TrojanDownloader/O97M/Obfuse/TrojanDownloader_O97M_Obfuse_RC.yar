
rule TrojanDownloader_O97M_Obfuse_RC{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RC,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 6c 65 63 74 69 6f 6e 2e 49 6e 73 65 72 74 42 65 66 6f 72 65 } //01 00  Selection.InsertBefore
		$a_01_1 = {45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } //01 00  Environ("USERPROFILE")
		$a_01_2 = {26 20 22 2e 6a 73 65 22 } //01 00  & ".jse"
		$a_01_3 = {2e 57 72 69 74 65 20 6a 73 54 65 78 74 34 54 65 78 74 } //01 00  .Write jsText4Text
		$a_01_4 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00  .ShellExecute
		$a_01_5 = {26 20 64 61 65 61 66 } //00 00  & daeaf
	condition:
		any of ($a_*)
 
}