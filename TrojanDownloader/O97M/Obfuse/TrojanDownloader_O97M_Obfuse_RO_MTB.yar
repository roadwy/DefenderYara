
rule TrojanDownloader_O97M_Obfuse_RO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 56 61 6c 28 22 26 48 22 20 26 20 28 4d 69 64 24 28 } //01 00  = Val("&H" & (Mid$(
		$a_01_1 = {31 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 } //01 00  1) = Chr(Asc(Mid(
		$a_03_2 = {2e 52 75 6e 20 22 22 20 2b 20 90 02 60 20 2b 20 22 20 22 20 2b 90 00 } //01 00 
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 90 02 60 2c 20 22 90 00 } //01 00 
		$a_03_4 = {3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 60 29 90 02 15 4d 69 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_RO_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 3d 20 22 22 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 61 22 22 } //01 00   = """m" + "s" + "h" + "ta""
		$a_03_1 = {25 32 30 25 32 30 40 6a 2e 6d 70 2f 6c 6f 76 65 32 34 32 34 32 6b 61 64 61 32 72 90 0a 3f 00 68 74 74 70 3a 2f 2f 90 00 } //02 00 
		$a_01_2 = {68 74 74 70 73 22 20 2b 20 22 3a 2f 2f 25 36 37 38 36 64 37 38 61 73 64 22 20 2b 20 22 25 36 37 38 36 64 37 38 61 73 64 25 22 20 2b 20 22 36 37 38 36 64 37 38 61 73 64 25 36 37 38 36 64 37 38 61 73 64 40 6a 2e 6d 70 22 20 2b 20 } //00 00  https" + "://%6786d78asd" + "%6786d78asd%" + "6786d78asd%6786d78asd@j.mp" + 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_RO_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 25 34 30 40 6a 2e 6d 70 2f 61 73 64 67 68 61 73 64 35 36 37 61 73 64 67 68 22 90 0a 4f 00 74 61 20 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_03_1 = {25 32 30 25 32 30 40 6a 2e 6d 70 2f 90 0a 3f 00 70 3a 2f 2f 90 00 } //01 00 
		$a_03_2 = {20 3d 20 22 6d 22 0d 0a 90 02 0f 20 3d 20 22 73 22 0d 0a 90 02 0f 20 3d 20 22 68 22 0d 0a 90 02 0f 20 3d 20 22 74 22 0d 0a 90 02 0f 20 3d 20 22 61 90 02 03 22 90 00 } //02 00 
		$a_01_3 = {68 22 20 2b 20 22 74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 73 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b 20 22 6a 22 20 2b 20 22 2e 22 20 2b 20 22 6d 22 20 2b 20 22 70 22 20 2b 20 22 2f 22 20 2b } //00 00  h" + "t" + "t" + "p" + "s" + ":" + "/" + "/" + "j" + "." + "m" + "p" + "/" +
	condition:
		any of ($a_*)
 
}