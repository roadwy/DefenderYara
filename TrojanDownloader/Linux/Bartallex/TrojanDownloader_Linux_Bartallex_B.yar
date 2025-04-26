
rule TrojanDownloader_Linux_Bartallex_B{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.B,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {39 31 2e 32 32 30 2e 31 33 31 2e 37 33 2f 63 61 2f 66 69 6c 65 } //1 91.220.131.73/ca/file
		$a_01_1 = {43 68 72 28 41 73 63 28 22 70 22 29 29 20 2b 20 43 68 72 28 41 73 63 28 22 69 22 29 29 20 2b 20 22 66 22 20 2b 20 43 68 72 28 33 34 29 } //1 Chr(Asc("p")) + Chr(Asc("i")) + "f" + Chr(34)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Linux_Bartallex_B_2{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.B,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 61 73 69 67 75 61 6e 61 73 2e 63 6f 6d 2e 6d 78 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 63 68 72 6f 6d 65 } //1 lasiguanas.com.mx/wp-content/plugins/chrome
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 53 65 72 76 65 72 58 4d 4c 48 54 54 50 22 29 } //1 CreateObject("MSXML2.ServerXMLHTTP")
		$a_01_2 = {22 2e 76 22 20 2b 20 22 62 22 20 2b 20 22 73 22 } //1 ".v" + "b" + "s"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule TrojanDownloader_Linux_Bartallex_B_3{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.B,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 72 69 74 73 63 68 66 69 73 63 68 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 32 30 31 31 2f 30 38 2f 6c 69 63 65 6e 73 65 } //1 www.ritschfisch.com/wp-content/uploads/2011/08/license
		$a_01_1 = {43 68 72 28 33 34 29 20 2b 20 22 34 2e 65 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 2b 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 78 65 22 20 2b 20 43 68 72 28 33 34 29 } //1 Chr(34) + "4.e" + Chr(34) + "+" + Chr(34) + "xe" + Chr(34)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Linux_Bartallex_B_4{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.B,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 0a 00 00 "
		
	strings :
		$a_00_0 = {76 65 70 69 63 2e 73 75 2f } //1 vepic.su/
		$a_00_1 = {73 61 76 65 70 69 63 2e 73 75 2f } //1 savepic.su/
		$a_01_2 = {6f 62 6a 41 44 4f 53 74 72 65 61 6d 2e 4f 70 65 6e } //1 objADOStream.Open
		$a_00_3 = {6d 70 5c 22 20 2b 20 42 41 52 54 } //1 mp\" + BART
		$a_01_4 = {4b 69 6c 6c 20 58 50 46 49 4c 45 44 49 52 } //1 Kill XPFILEDIR
		$a_01_5 = {4b 69 6c 6c 20 55 57 47 44 } //1 Kill UWGD
		$a_00_6 = {42 41 52 54 20 3d 20 22 22 20 2b 20 42 41 52 54 32 20 2b 20 43 68 72 } //1 BART = "" + BART2 + Chr
		$a_00_7 = {3a 2f 2f 22 20 2b 20 55 52 4c 4c 53 4b 20 2b 20 22 2e 22 20 2b 20 43 68 72 28 41 73 63 28 22 65 22 29 29 20 2b 20 43 68 72 28 41 73 63 28 22 78 22 29 29 20 2b 20 22 65 22 } //1 ://" + URLLSK + "." + Chr(Asc("e")) + Chr(Asc("x")) + "e"
		$a_01_8 = {4b 69 6c 6c 20 4d 59 5f 46 49 4c 45 4e 44 49 52 } //1 Kill MY_FILENDIR
		$a_01_9 = {43 68 72 28 41 73 63 28 22 78 22 29 29 20 2b 20 43 68 72 28 41 73 63 28 22 65 22 29 29 } //1 Chr(Asc("x")) + Chr(Asc("e"))
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=4
 
}