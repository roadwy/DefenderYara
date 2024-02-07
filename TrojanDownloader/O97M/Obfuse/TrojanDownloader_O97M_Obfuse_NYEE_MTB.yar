
rule TrojanDownloader_O97M_Obfuse_NYEE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NYEE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 72 6f 67 72 61 6d 73 74 69 6c 6c 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 73 69 6e 67 6c 65 72 69 73 6b 2e 62 61 74 22 } //01 00  programstill = "C:\Users\Public\Documents\singlerisk.bat"
		$a_01_1 = {22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 70 73 3a 2f 2f 63 61 72 67 6f 74 72 61 6e 73 2d 67 69 6f 62 61 6c 2e 63 6f 6d 2f 68 2f 72 72 72 2e 65 78 65 } //01 00  " -w h Start-BitsTransfer -Source https://cargotrans-giobal.com/h/rrr.exe
		$a_01_2 = {2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 49 4d 72 2e 65 78 65 3b } //01 00  -Destination C:\Users\Public\Documents\IMr.exe;
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  = CreateObject("Shell.Application")
		$a_01_4 = {43 61 6c 6c 20 77 6f 6d 61 6e 6c 65 61 72 6e 2e 4f 70 65 6e 28 70 72 6f 67 72 61 6d 73 74 69 6c 6c 29 } //00 00  Call womanlearn.Open(programstill)
	condition:
		any of ($a_*)
 
}