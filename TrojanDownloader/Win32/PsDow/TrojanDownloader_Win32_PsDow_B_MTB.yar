
rule TrojanDownloader_Win32_PsDow_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/PsDow.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 } //2 New-Object System.Net.WebClient
		$a_01_1 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 } //2 .DownloadFile(
		$a_01_2 = {4e 65 77 2d 4f 62 6a 65 63 74 20 2d 63 6f 6d 20 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e } //2 New-Object -com shell.application
		$a_01_3 = {2e 73 68 65 6c 6c 65 78 65 63 75 74 65 28 } //2 .shellexecute(
		$a_01_4 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 } //2 powershell -ExecutionPolicy Bypass -F
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}