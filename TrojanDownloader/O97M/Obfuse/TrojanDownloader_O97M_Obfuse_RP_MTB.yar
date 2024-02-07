
rule TrojanDownloader_O97M_Obfuse_RP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 56 61 6c 28 22 26 48 22 20 26 20 28 4d 69 64 24 28 } //01 00  = Val("&H" & (Mid$(
		$a_01_1 = {3d 20 41 73 63 28 4d 69 64 24 28 } //01 00  = Asc(Mid$(
		$a_01_2 = {3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 } //01 00  = Chr(Asc(Mid(
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 90 02 60 2c 20 22 90 02 60 22 2c 20 22 22 29 90 00 } //01 00 
		$a_03_4 = {2e 52 75 6e 20 22 22 20 2b 20 90 02 60 20 2b 20 22 20 22 20 2b 90 00 } //01 00 
		$a_03_5 = {3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 60 29 90 02 20 4d 69 64 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}