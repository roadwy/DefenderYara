
rule TrojanDownloader_O97M_Obfuse_BBO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BBO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 6e 76 69 72 6f 6e 24 28 22 55 73 65 72 44 6f 6d 61 69 6e 22 29 20 26 20 22 5c 22 20 26 20 45 6e 76 69 72 6f 6e 24 28 22 43 6f 6d 70 75 74 65 72 4e 61 6d 65 22 29 20 26 20 22 5c 22 20 26 20 45 6e 76 69 72 6f 6e 24 28 22 55 73 65 72 6e 61 6d 65 22 29 } //1 Environ$("UserDomain") & "\" & Environ$("ComputerName") & "\" & Environ$("Username")
		$a_01_1 = {3d 20 57 73 68 53 68 65 6c 6c 2e 45 78 65 63 28 22 74 61 73 6b 6b 69 6c 6c 20 2f 66 69 20 22 22 69 6d 61 67 65 6e 61 6d 65 20 65 71 20 6d 73 65 64 67 65 2e 65 78 65 22 22 22 29 } //1 = WshShell.Exec("taskkill /fi ""imagename eq msedge.exe""")
		$a_01_2 = {3d 20 57 73 68 53 68 65 6c 6c 2e 45 78 65 63 28 22 74 61 73 6b 6b 69 6c 6c 20 2f 66 69 20 22 22 69 6d 61 67 65 6e 61 6d 65 20 65 71 20 69 65 78 70 6c 6f 72 65 72 2e 65 78 65 22 22 22 29 } //1 = WshShell.Exec("taskkill /fi ""imagename eq iexplorer.exe""")
		$a_01_3 = {43 61 6c 6c 20 53 68 6f 77 5f 53 68 65 65 74 73 } //1 Call Show_Sheets
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}