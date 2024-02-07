
rule TrojanDownloader_O97M_Malshelcpt_DD{
	meta:
		description = "TrojanDownloader:O97M/Malshelcpt.DD,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 31 33 2e 78 6c 73 78 } //01 00  Environ("TEMP") & "\13.xlsx
		$a_00_1 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 27 26 20 22 5c 55 6e 7a 54 6d 70 } //01 00  Environ("TEMP") '& "\UnzTmp
		$a_00_2 = {41 44 41 54 41 20 2b 20 22 5c 65 78 63 68 61 6e 67 65 32 2e 64 6c 6c } //01 00  ADATA + "\exchange2.dll
		$a_00_3 = {53 65 74 20 6f 41 70 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  Set oApp = CreateObject("Shell.Application")
		$a_00_4 = {6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 5a 69 70 46 6f 6c 64 65 72 29 2e 43 6f 70 79 48 65 72 65 20 6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 5a 69 70 4e 61 6d 65 29 2e 69 74 65 6d 73 2e 49 74 65 6d 28 22 78 6c 5c 65 6d 62 65 64 64 69 6e 67 73 5c 6f 6c 65 4f 62 6a 65 63 74 31 2e 62 69 6e 22 29 } //01 00  oApp.Namespace(ZipFolder).CopyHere oApp.Namespace(ZipName).items.Item("xl\embeddings\oleObject1.bin")
		$a_00_5 = {52 65 61 64 41 6e 64 57 72 69 74 65 45 78 74 72 61 63 74 65 64 42 69 6e 46 69 6c 65 20 5a 69 70 46 6f 6c 64 65 72 20 2b 20 22 5c 6f 6c 65 4f 62 6a 65 63 74 31 2e 62 69 6e 22 2c 20 6e 6d 2c 20 73 69 7a 65 2c 20 6e 75 6d } //00 00  ReadAndWriteExtractedBinFile ZipFolder + "\oleObject1.bin", nm, size, num
	condition:
		any of ($a_*)
 
}