
rule TrojanDownloader_O97M_Powdow_BNQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BNQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 72 20 26 20 72 73 68 65 6c 6c 20 26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 } //1 powerr & rshell & " -w h Start-BitsTransfer -Source
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 63 61 72 67 6f 74 72 61 6e 73 2d 67 69 6f 62 61 6c 2e 63 6f 6d 2f 68 2f 66 69 6c 65 2e 65 78 65 } //1 https://cargotrans-giobal.com/h/file.exe
		$a_03_2 = {44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-14] 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}