
rule TrojanDownloader_O97M_Powdow_BBS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BBS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 20 63 76 67 6b 6a 77 47 33 34 37 72 74 48 44 46 46 47 65 34 36 2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 20 26 20 68 72 6b 77 64 6a 6b 73 64 6a 62 6b 2c 20 30 } //1 .Run cvgkjwG347rtHDFFGe46.TextBox1.Text & hrkwdjksdjbk, 0
		$a_01_1 = {3d 20 43 65 6c 6c 73 28 73 64 66 67 68 61 73 64 41 53 66 48 53 64 72 74 73 79 67 34 36 73 64 72 67 61 73 64 66 2c 20 63 64 76 67 6e 66 68 61 69 77 75 65 74 34 75 54 68 53 64 47 33 34 74 29 } //1 = Cells(sdfghasdASfHSdrtsyg46sdrgasdf, cdvgnfhaiwuet4uThSdG34t)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Powdow_BBS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BBS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 77 20 68 69 20 73 6c 65 65 5e 70 20 2d 53 65 20 33 31 3b 53 74 61 5e 72 74 2d 42 69 74 73 54 72 5e 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 } //1 -w hi slee^p -Se 31;Sta^rt-BitsTr^ansfer -Source htt
		$a_01_1 = {2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6c 69 6e 65 73 65 72 69 65 73 2e 65 60 78 65 } //1 -Destination C:\Users\Public\Documents\lineseries.e`xe
		$a_01_2 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 77 68 65 6e 73 74 65 70 2e 63 6d 22 20 26 20 43 68 72 28 43 4c 6e 67 28 22 39 39 2e 36 22 29 29 } //1 = "C:\Users\Public\Documents\whenstep.cm" & Chr(CLng("99.6"))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}