
rule TrojanDownloader_O97M_Onchro_A{
	meta:
		description = "TrojanDownloader:O97M/Onchro.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 20 3d 20 42 61 73 65 36 34 44 65 63 6f 64 65 28 22 61 48 52 30 63 44 6f 76 4c 7a 45 77 4d 79 34 79 4e 54 55 75 4d 54 41 78 4c 6a 59 30 4c 33 35 76 62 6a 6c 6a 61 47 39 77 } //1 s = Base64Decode("aHR0cDovLzEwMy4yNTUuMTAxLjY0L35vbjljaG9w
		$a_00_1 = {73 31 20 3d 20 6f 53 68 65 6c 6c 2e 65 78 70 61 6e 64 65 6e 76 69 72 6f 6e 6d 65 6e 74 73 74 72 69 6e 67 73 28 22 25 54 65 6d 70 25 22 29 20 26 20 22 5c 63 68 72 6f 6d 65 2e 65 78 65 22 } //1 s1 = oShell.expandenvironmentstrings("%Temp%") & "\chrome.exe"
		$a_00_2 = {6f 53 68 65 6c 6c 2e 52 75 6e 20 28 73 31 29 } //1 oShell.Run (s1)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}