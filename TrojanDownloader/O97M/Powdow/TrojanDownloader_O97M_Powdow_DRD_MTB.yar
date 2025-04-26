
rule TrojanDownloader_O97M_Powdow_DRD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DRD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 61 70 70 64 61 74 61 25 22 29 20 26 20 22 5c 42 61 64 46 69 6c 65 2e 65 22 20 26 20 22 78 65 22 } //1 .ExpandEnvironmentStrings("%appdata%") & "\BadFile.e" & "xe"
		$a_03_1 = {6c 61 73 74 6c 69 6e 65 64 65 6d 6f 2e 63 6f 6d 2f 64 65 6d 6f 2f 74 65 73 74 66 69 6c 65 73 2f 73 61 6d 70 6c 65 2f 73 61 6d 70 6c 65 5f 65 78 65 5f 30 30 2e 65 78 65 90 0a 3f 00 68 74 74 70 3a 2f 2f } //1
		$a_01_2 = {2e 52 75 6e 20 22 25 43 4f 4d 53 50 45 43 25 20 2f 43 22 20 26 20 72 75 6e 43 6d 64 } //1 .Run "%COMSPEC% /C" & runCmd
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 24 77 65 62 43 6c 69 65 6e 74 20 3d 20 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 3b 20 24 77 65 62 43 6c 69 65 6e 74 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 22 20 26 20 66 69 6c 65 4c 6f 63 } //1 powershell.exe $webClient = New-Object System.Net.WebClient; $webClient.DownloadFile('" & fileLoc
		$a_01_4 = {52 75 6e 5f 50 72 6f 67 72 61 6d 20 70 61 79 6c 6f 61 64 4c 6f 63 } //1 Run_Program payloadLoc
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}