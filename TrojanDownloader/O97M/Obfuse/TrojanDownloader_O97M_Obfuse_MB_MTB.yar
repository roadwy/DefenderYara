
rule TrojanDownloader_O97M_Obfuse_MB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 65 67 57 72 69 74 65 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 5c 22 2c 20 22 22 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 22 22 22 22 68 74 74 70 73 3a 5c 5c 62 69 74 2e 6c 79 2f 90 02 1e 22 22 22 2c 20 22 52 45 47 5f 53 5a 22 90 00 } //01 00 
		$a_01_1 = {53 75 62 20 41 75 74 6f 5f 43 6c 6f 73 65 28 29 } //00 00  Sub Auto_Close()
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_MB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 15 2e 43 6f 6e 74 72 6f 6c 73 28 31 29 2e 56 61 6c 75 65 2c 20 54 72 75 65 29 90 00 } //01 00 
		$a_03_1 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 90 02 15 2e 43 6f 6e 74 72 6f 6c 73 28 30 29 2e 43 61 70 74 69 6f 6e 29 90 00 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  CreateObject("Shell.Application")
		$a_03_3 = {43 61 6c 6c 20 90 02 15 2e 4f 70 65 6e 28 90 02 15 2e 43 6f 6e 74 72 6f 6c 73 28 31 29 2e 56 61 6c 75 65 29 90 00 } //01 00 
		$a_01_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00  = CreateObject("Scripting.FileSystemObject")
		$a_01_5 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00  Sub AutoOpen()
		$a_01_6 = {2e 43 6c 6f 73 65 } //00 00  .Close
	condition:
		any of ($a_*)
 
}