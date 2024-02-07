
rule TrojanDownloader_O97M_Obfuse_NH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 29 } //01 00  (Environ("TEMP"))
		$a_01_1 = {3d 53 65 63 74 69 6f 6e 2e 50 61 72 65 6e 74 2e 50 61 74 68 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 61 74 68 53 65 70 61 72 61 74 6f 72 20 26 20 6e 61 6d 65 20 26 20 22 2e 68 74 6d 22 2c 20 5f } //01 00  =Section.Parent.Path & Application.PathSeparator & name & ".htm", _
		$a_01_2 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 43 6c 6f 73 65 } //01 00  ThisDocument.Close
		$a_03_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 14 2e 54 61 67 29 90 00 } //01 00 
		$a_03_4 = {4f 70 65 6e 20 90 02 14 20 46 6f 72 20 42 69 6e 61 72 79 20 4c 6f 63 6b 20 52 65 61 64 20 57 72 69 74 65 20 41 73 20 23 90 00 } //01 00 
		$a_01_5 = {50 75 74 20 23 } //01 00  Put #
		$a_01_6 = {2e 53 65 6e 64 4d 65 73 73 61 67 65 20 30 2c 20 30 2c 20 30 2c 20 30 } //01 00  .SendMessage 0, 0, 0, 0
		$a_01_7 = {6e 61 6d 65 20 3d 20 52 65 70 6c 61 63 65 28 48 65 61 64 65 72 2e 54 65 78 74 2c 20 43 68 72 28 31 33 29 2c 20 22 22 29 } //00 00  name = Replace(Header.Text, Chr(13), "")
	condition:
		any of ($a_*)
 
}