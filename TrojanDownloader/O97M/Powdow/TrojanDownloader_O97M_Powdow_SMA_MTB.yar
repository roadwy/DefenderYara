
rule TrojanDownloader_O97M_Powdow_SMA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SMA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 44 6f 77 6e 22 20 26 20 22 6c 6f 61 22 20 26 20 22 64 53 74 72 22 20 26 20 22 69 6e 67 28 20 27 68 74 74 70 73 3a 2f 2f 70 74 2e 74 65 78 74 62 69 6e 2e 6e 65 74 2f 64 6f 77 6e 6c 6f 61 64 2f 78 37 73 66 36 74 32 64 67 76 27 20 29 } //1 .Down" & "loa" & "dStr" & "ing( 'https://pt.textbin.net/download/x7sf6t2dgv' )
		$a_01_1 = {7c 20 4f 75 74 2d 46 69 6c 65 20 2d 46 69 6c 65 50 61 74 68 20 78 2e 6a 73 20 2d 66 6f 72 63 65 } //1 | Out-File -FilePath x.js -force
		$a_03_2 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 6f 6d 6d 61 6e 64 20 22 20 26 20 [0-1f] 20 26 20 22 20 3b 20 65 78 69 74 20 22 2c 20 76 62 48 69 64 65 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SMA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SMA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4d 6f 64 75 6c 65 31 31 22 [0-03] 53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 [0-03] 4d 73 67 42 6f 78 20 22 45 72 72 6f 72 21 21 } //1
		$a_01_1 = {53 65 74 20 6f 62 6a 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 Set objShell = CreateObject("Shell.Application")
		$a_03_2 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f [0-25] 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}