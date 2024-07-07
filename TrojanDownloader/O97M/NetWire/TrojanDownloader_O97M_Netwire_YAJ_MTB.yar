
rule TrojanDownloader_O97M_Netwire_YAJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Netwire.YAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 27 29 2e 49 6e 76 6f 6b 65 28 28 27 68 74 27 2b 27 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 44 67 77 58 43 6d 4d } //1 DownloadFile').Invoke(('ht'+'tps://cutt.ly/DgwXCmM
		$a_01_1 = {70 6f 5e 77 65 72 5e 73 68 65 6c 6c 20 2d 77 20 31 20 53 74 61 72 74 2d 53 6c 65 65 70 20 31 36 3b 20 73 54 41 72 74 2d 60 50 60 52 60 6f 63 65 73 73 20 24 65 6e 76 3a 61 70 70 64 61 74 61 5c 6b 63 2e 65 78 65 } //1 po^wer^shell -w 1 Start-Sleep 16; sTArt-`P`R`ocess $env:appdata\kc.exe
		$a_01_2 = {70 5e 6f 77 65 72 5e 73 68 65 6c 6c 20 2d 77 20 31 20 53 74 61 72 74 2d 53 6c 65 65 70 20 31 30 3b 20 4d 6f 76 65 2d 49 74 65 6d 20 22 6b 63 2e 65 78 65 } //1 p^ower^shell -w 1 Start-Sleep 10; Move-Item "kc.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}