
rule TrojanDownloader_O97M_Powdow_TNY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.TNY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 5e 77 65 72 5e 73 68 65 6c 6c 20 2d 77 } //01 00  po^wer^shell -w
		$a_01_1 = {28 27 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 27 29 } //01 00  ('DownloadFile')
		$a_01_2 = {49 6e 76 6f 6b 65 28 28 27 68 74 27 2b 27 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 36 74 63 64 39 36 74 27 29 2c 27 6b 63 2e 65 78 65 27 29 } //00 00  Invoke(('ht'+'tps://tinyurl.com/y6tcd96t'),'kc.exe')
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_TNY_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.TNY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 70 6f 77 65 5e 72 73 68 65 6c 6c 20 2d 77 20 31 20 28 6e 45 77 2d 6f 42 6a 65 60 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } //01 00  cmd /cpowe^rshell -w 1 (nEw-oBje`cT Net.WebcL`IENt)
		$a_01_1 = {28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //01 00  ('Down'+'loadFile')
		$a_01_2 = {49 6e 76 6f 6b 65 22 22 28 27 68 74 74 70 73 3a 2f 2f 72 62 2e 67 79 2f 67 36 34 62 77 6a 27 2c 27 73 68 2e 65 78 65 27 29 } //01 00  Invoke""('https://rb.gy/g64bwj','sh.exe')
		$a_01_3 = {49 6e 76 6f 6b 65 22 22 28 27 68 74 74 70 73 3a 2f 2f 72 62 2e 67 79 2f 67 6c 79 77 65 76 27 2c 27 64 65 2e 65 78 65 27 29 } //00 00  Invoke""('https://rb.gy/glywev','de.exe')
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_TNY_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.TNY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 5e 6f 77 65 72 73 68 65 6c 6c 20 2d 77 20 31 } //01 00  p^owershell -w 1
		$a_01_1 = {28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //01 00  ('Down'+'loadFile')
		$a_01_2 = {53 74 61 72 74 2d 53 6c 65 65 70 20 34 30 } //01 00  Start-Sleep 40
		$a_01_3 = {49 6e 76 6f 6b 65 22 22 28 27 68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 35 67 71 32 39 66 76 27 2c 27 70 64 2e 62 61 74 27 29 } //01 00  Invoke""('https://tinyurl.com/y5gq29fv','pd.bat')
		$a_01_4 = {49 6e 76 6f 6b 65 22 22 28 27 68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 34 62 70 33 38 7a 33 27 2c 27 70 64 2e 62 61 74 27 29 22 29 } //01 00  Invoke""('https://tinyurl.com/y4bp38z3','pd.bat')")
		$a_01_5 = {49 6e 76 6f 6b 65 22 22 28 27 68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 32 63 78 70 73 33 32 27 2c 27 70 64 2e 62 61 74 27 29 22 29 } //00 00  Invoke""('https://tinyurl.com/y2cxps32','pd.bat')")
	condition:
		any of ($a_*)
 
}