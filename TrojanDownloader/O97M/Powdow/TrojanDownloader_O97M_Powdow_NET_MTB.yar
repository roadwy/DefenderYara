
rule TrojanDownloader_O97M_Powdow_NET_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.NET!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 72 6c 3d 27 68 74 74 70 73 3a 2f 2f 6e 73 6f 66 74 6f 6e 6c 69 6e 65 2e 63 6f 6d 2f 6d 63 72 2f 73 68 69 70 61 72 74 69 63 75 6c 61 72 73 2e 65 78 65 27 } //1 url='https://nsoftonline.com/mcr/shiparticulars.exe'
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 20 } //1 powershell.exe -ExecutionPolicy Bypass -Command 
		$a_01_2 = {3d 27 43 3a 5c 55 73 65 72 73 5c 55 53 45 52 5c 44 6f 63 75 6d 65 6e 74 73 5c 73 68 69 70 61 72 74 69 63 75 6c 61 72 73 2e 65 78 65 27 3b 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 } //1 ='C:\Users\USER\Documents\shiparticulars.exe'; Invoke-WebRequest
		$a_01_3 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 24 6f 75 74 70 75 74 20 2d 4e 6f 4e 65 77 57 69 6e 64 6f 77 20 2d 57 61 69 74 } //1 Start-Process -FilePath $output -NoNewWindow -Wait
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}