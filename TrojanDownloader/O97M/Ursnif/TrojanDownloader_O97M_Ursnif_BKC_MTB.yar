
rule TrojanDownloader_O97M_Ursnif_BKC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.BKC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 43 6c 65 61 72 44 6f 63 75 6d 65 6e 74 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 22 20 26 20 4c 69 73 74 42 6f 78 31 2e 4c 69 73 74 28 33 29 2c 20 46 61 6c 73 65 } //01 00  GlobalClearDocument.Open "GET", "http://" & ListBox1.List(3), False
		$a_01_1 = {52 69 67 68 74 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 54 6f 46 69 6c 65 20 28 22 43 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 66 74 72 2e 63 70 6c 22 29 } //01 00  RightDocument.SaveToFile ("C:\users\public\ftr.cpl")
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4c 69 73 74 42 6f 78 31 2e 4c 69 73 74 28 34 29 29 2e 52 75 6e 20 28 4c 69 6e 6b 4e 61 6d 65 73 70 61 63 65 52 65 66 20 2b 20 22 43 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 66 74 72 2e 63 70 6c 22 29 } //01 00  CreateObject(ListBox1.List(4)).Run (LinkNamespaceRef + "C:\users\public\ftr.cpl")
		$a_01_3 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 73 79 73 74 65 6d 6c 69 76 65 2e 63 61 73 61 2f 73 74 61 74 69 73 31 63 2e 64 6c 6c 22 29 } //01 00  ListBox1.AddItem ("systemlive.casa/statis1c.dll")
		$a_01_4 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 72 65 67 73 76 72 33 32 20 22 29 } //01 00  ListBox1.AddItem ("regsvr32 ")
		$a_01_5 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  ListBox1.AddItem ("WScript.Shell")
		$a_01_6 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 44 65 66 22 } //00 00  Application.Run "Def"
	condition:
		any of ($a_*)
 
}