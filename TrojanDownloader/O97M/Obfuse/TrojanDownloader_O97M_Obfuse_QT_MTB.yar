
rule TrojanDownloader_O97M_Obfuse_QT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {2b 20 53 67 6e 28 49 6e 53 74 72 28 31 2c 20 [0-25] 2c 20 4d 69 64 28 [0-20] 2c 20 31 29 2c 20 76 62 42 69 6e 61 72 79 43 6f 6d 70 61 72 65 29 29 } //1
		$a_03_1 = {3d 20 31 20 54 6f 20 4c 65 6e 28 [0-25] 29 20 53 74 65 70 20 } //1
		$a_01_2 = {26 20 22 34 62 } //1 & "4b
		$a_01_3 = {26 20 22 35 } //1 & "5
		$a_01_4 = {26 20 22 37 } //1 & "7
		$a_01_5 = {33 33 33 34 33 33 } //1 333433
		$a_01_6 = {3d 20 49 73 4e 75 6c 6c 28 22 22 29 } //1 = IsNull("")
		$a_01_7 = {3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //1 = "1Normal.ThisDocument"
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule TrojanDownloader_O97M_Obfuse_QT_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 22 20 26 20 44 65 73 61 78 6f 70 20 26 20 22 22 20 26 20 22 5c 47 69 2e 22 20 26 20 22 22 20 26 20 22 6a 22 20 26 20 22 22 20 26 20 22 73 22 20 26 20 22 22 20 26 20 22 65 22 } //1 = "" & Desaxop & "" & "\Gi." & "" & "j" & "" & "s" & "" & "e"
		$a_01_1 = {4d 65 72 74 6f 70 39 20 3d 20 22 22 20 26 20 22 73 22 20 26 20 22 22 20 26 20 22 68 22 20 26 20 22 22 20 26 20 22 65 6c 22 20 26 20 22 6c 22 20 26 20 22 22 } //1 Mertop9 = "" & "s" & "" & "h" & "" & "el" & "l" & ""
		$a_01_2 = {26 20 45 6d 70 74 79 20 26 20 22 5c 54 65 73 6c 61 22 20 26 20 45 6d 70 74 79 } //1 & Empty & "\Tesla" & Empty
		$a_01_3 = {26 20 22 22 22 22 2c 20 30 } //1 & """", 0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}