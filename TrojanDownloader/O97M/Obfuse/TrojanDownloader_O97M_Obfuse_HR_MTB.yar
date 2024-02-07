
rule TrojanDownloader_O97M_Obfuse_HR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_03_1 = {31 39 35 2e 31 32 33 2e 32 34 31 2e 31 34 34 2f 61 70 69 2e 70 68 70 90 0a 1e 00 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_00_2 = {43 3a 5c 56 65 72 74 69 73 5c 4b 6f 74 73 5c 73 76 63 68 6f 73 74 } //01 00  C:\Vertis\Kots\svchost
		$a_00_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00  ShellExecuteA
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_HR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00  Sub AutoOpen()
		$a_03_1 = {2e 56 61 6c 75 65 29 2e 52 75 6e 25 20 90 02 30 28 32 29 20 2b 20 90 02 30 28 30 29 2c 90 00 } //01 00 
		$a_03_2 = {2e 52 75 6e 25 20 90 02 20 28 90 02 14 2e 43 6f 6e 74 72 6f 6c 73 2c 20 32 29 20 2b 90 00 } //01 00 
		$a_01_3 = {2e 43 6f 6e 74 72 6f 6c 73 } //01 00  .Controls
		$a_01_4 = {3d 20 53 71 72 28 34 29 20 2d 20 31 } //00 00  = Sqr(4) - 1
	condition:
		any of ($a_*)
 
}