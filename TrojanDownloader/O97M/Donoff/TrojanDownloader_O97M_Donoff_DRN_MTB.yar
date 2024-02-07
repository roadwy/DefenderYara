
rule TrojanDownloader_O97M_Donoff_DRN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DRN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 44 65 73 6b 74 6f 70 5c 22 } //01 00  Environ("USERPROFILE") & "\Desktop\"
		$a_01_1 = {73 50 61 74 68 20 2b 20 22 57 72 7a 6f 64 2e 65 78 65 22 } //01 00  sPath + "Wrzod.exe"
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 42 28 55 52 4c 2c 20 4c 6f 63 61 6c 46 69 6c 65 6e 61 6d 65 2c 20 22 22 2c 20 22 22 29 } //01 00  DownloadFileB(URL, LocalFilename, "", "")
		$a_01_3 = {73 50 61 74 68 20 2b 20 52 65 70 6c 61 63 65 28 22 57 72 7a 6f 64 2e 21 78 21 22 2c 20 22 21 22 2c 20 22 65 22 29 } //01 00  sPath + Replace("Wrzod.!x!", "!", "e")
		$a_01_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  CreateObject("Wscript.Shell")
		$a_01_5 = {6f 62 6a 53 2e 52 75 6e 20 73 46 69 6c 65 } //01 00  objS.Run sFile
		$a_03_6 = {77 72 7a 6f 64 2e 76 78 6d 2e 70 6c 2f 57 72 7a 6f 64 90 0a 26 00 68 74 74 70 73 3a 2f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_DRN_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DRN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 6c 70 69 35 72 5a 5f 5f 6a 6d 45 79 5a 4b 49 6a 47 4a 35 4c 45 } //01 00  Salpi5rZ__jmEyZKIjGJ5LE
		$a_01_1 = {43 68 72 28 64 73 5f 66 20 2d 20 37 37 29 } //01 00  Chr(ds_f - 77)
		$a_01_2 = {64 5f 66 67 28 31 36 34 29 20 26 20 64 5f 66 67 28 31 36 30 29 20 26 20 64 5f 66 67 28 31 34 34 29 20 26 20 64 5f 66 67 28 31 39 31 29 20 26 20 64 5f 66 67 28 31 38 32 29 20 26 20 64 5f 66 67 28 31 38 39 29 20 26 20 64 5f 66 67 28 31 36 31 29 20 26 20 64 5f 66 67 28 31 32 33 29 20 26 20 64 5f 66 67 28 31 39 32 29 20 26 20 64 5f 66 67 28 31 34 39 29 20 26 20 64 5f 66 67 28 31 34 36 29 20 26 20 64 5f 66 67 28 31 38 35 29 20 26 20 64 5f 66 67 28 31 35 33 29 } //01 00  d_fg(164) & d_fg(160) & d_fg(144) & d_fg(191) & d_fg(182) & d_fg(189) & d_fg(161) & d_fg(123) & d_fg(192) & d_fg(149) & d_fg(146) & d_fg(185) & d_fg(153)
		$a_01_3 = {7a 57 61 59 75 4d 59 5f 41 45 56 68 5f 63 66 41 31 79 45 69 45 4d 49 58 65 6b 5f 74 68 } //01 00  zWaYuMY_AEVh_cfA1yEiEMIXek_th
		$a_01_4 = {67 66 67 68 62 20 62 76 63 76 6e 62 63 20 62 76 63 6e 63 6d } //00 00  gfghb bvcvnbc bvcncm
	condition:
		any of ($a_*)
 
}