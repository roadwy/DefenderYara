
rule TrojanDownloader_O97M_Powdow_RW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //01 00  powershell.exe
		$a_03_1 = {74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 32 78 73 7a 62 32 6a 90 0a 1f 00 68 74 27 2b 27 74 70 73 3a 2f 2f 90 00 } //01 00 
		$a_00_2 = {4f 75 74 46 69 6c 65 } //01 00  OutFile
		$a_00_3 = {74 65 73 74 35 27 2b 27 2e 65 78 65 27 } //00 00  test5'+'.exe'
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_RW_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 61 2e 65 78 65 63 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 61 2e 54 61 67 } //01 00  Ca.exec "explorer.exe " & a.Tag
		$a_00_1 = {54 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 27 54 22 29 } //01 00  T.WriteLine ("'T")
		$a_00_2 = {45 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 61 2e 54 61 67 2c 20 54 72 75 65 29 } //01 00  E.CreateTextFile(a.Tag, True)
		$a_00_3 = {54 2e 57 72 69 74 65 4c 69 6e 65 20 61 2e 62 2e 43 61 70 74 69 6f 6e } //01 00  T.WriteLine a.b.Caption
		$a_00_4 = {22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 } //00 00  "Scripting.FileSystemObject"
	condition:
		any of ($a_*)
 
}