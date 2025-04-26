
rule TrojanDownloader_O97M_Obfuse_PAD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 20 2d 63 6f 6d 6d 61 6e 64 } //powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass  -command  1
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 69 73 61 76 67 6f 2e 63 6f 6d 2f 6e 65 77 66 69 6c 65 2e 65 78 65 20 2d 4f 75 74 46 69 6c 65 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 61 72 74 77 72 6c 71 70 71 2e 65 78 65 } //https://isavgo.com/newfile.exe -OutFile C:\Users\Public\artwrlqpq.exe  1
		$a_80_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 61 72 74 77 72 6c 71 70 71 2e 65 78 65 } //Start-Process -FilePath "C:\Users\Public\artwrlqpq.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}