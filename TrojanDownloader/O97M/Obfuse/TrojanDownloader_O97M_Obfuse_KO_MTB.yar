
rule TrojanDownloader_O97M_Obfuse_KO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2e 6a 73 65 22 } //01 00  = ".jse"
		$a_01_1 = {6a 73 54 65 78 74 34 54 65 78 74 } //01 00  jsText4Text
		$a_03_2 = {54 65 78 74 3a 3d 22 3d 20 22 20 2b 20 90 02 13 20 2b 20 22 20 5c 2a 20 43 61 72 64 54 65 78 74 22 2c 20 5f 90 00 } //01 00 
		$a_01_3 = {3d 20 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 } //01 00  = "WScript.Shell"
		$a_01_4 = {3d 20 57 53 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 4d 79 44 6f 63 75 6d 65 6e 74 73 22 29 } //01 00  = WSShell.SpecialFolders("MyDocuments")
		$a_01_5 = {4f 70 65 6e 20 66 69 6c 65 32 73 61 76 72 73 61 76 65 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //00 00  Open file2savrsave For Output As #1
	condition:
		any of ($a_*)
 
}