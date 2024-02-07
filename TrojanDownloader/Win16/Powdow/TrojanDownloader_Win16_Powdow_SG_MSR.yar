
rule TrojanDownloader_Win16_Powdow_SG_MSR{
	meta:
		description = "TrojanDownloader:Win16/Powdow.SG!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 6f 6f 6b 73 74 6f 72 65 2e 6e 65 75 2e 65 64 75 2e 74 72 2f 4b 47 42 20 4e 75 6d 61 72 61 6c 61 72 69 20 76 65 20 47 65 63 65 72 6c 69 6c 69 6b 20 54 61 72 69 68 6c 65 72 69 2e 78 6c 73 78 } //01 00  bookstore.neu.edu.tr/KGB Numaralari ve Gecerlilik Tarihleri.xlsx
		$a_00_1 = {6d 79 55 52 4c 20 3d 20 63 6f 70 20 26 20 22 5c 54 65 6d 70 22 20 26 20 22 5c 66 69 6c 65 2e 78 6c 73 78 } //01 00  myURL = cop & "\Temp" & "\file.xlsx
		$a_00_2 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 46 69 6c 65 4e 61 6d 65 3a 3d 6d 79 55 52 4c 2c 20 50 61 73 73 77 6f 72 64 3a 3d 31 32 33 34 29 } //01 00  Workbooks.Open(FileName:=myURL, Password:=1234)
		$a_00_3 = {6f 62 6a 4e 6f 64 65 2e 44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 } //00 00  objNode.DataType = "bin.base64
	condition:
		any of ($a_*)
 
}