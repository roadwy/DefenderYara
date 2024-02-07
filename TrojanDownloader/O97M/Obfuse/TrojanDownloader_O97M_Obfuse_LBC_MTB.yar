
rule TrojanDownloader_O97M_Obfuse_LBC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LBC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 56 61 6c 28 22 26 48 22 20 26 20 28 4d 69 64 24 28 44 61 74 61 49 6e 2c 20 28 32 20 2a 20 6c 6f 6e 44 61 74 61 50 74 72 29 } //01 00  = Val("&H" & (Mid$(DataIn, (2 * lonDataPtr)
		$a_01_1 = {3d 20 41 73 63 28 4d 69 64 24 28 43 6f 64 65 4b 65 79 2c 20 28 28 6c 6f 6e 44 61 74 61 50 74 72 20 4d 6f 64 20 4c 65 6e 28 43 6f 64 65 4b 65 79 29 29 20 2b 20 31 29 2c 20 31 29 29 } //01 00  = Asc(Mid$(CodeKey, ((lonDataPtr Mod Len(CodeKey)) + 1), 1))
		$a_01_2 = {3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 69 2c 20 31 29 29 } //01 00  = Chr(Asc(Mid(strInput, i, 1))
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 90 02 60 2c 20 22 90 02 60 22 2c 20 22 22 29 90 02 15 2e 52 75 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}