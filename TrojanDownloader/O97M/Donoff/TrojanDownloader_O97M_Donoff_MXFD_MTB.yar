
rule TrojanDownloader_O97M_Donoff_MXFD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXFD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 22 29 } //1 CreateObject("MSXML2.DOMDocument")
		$a_01_1 = {78 6d 6c 44 6f 63 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //1 xmlDoc.createElement("b64")
		$a_01_2 = {64 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //1 dataType = "bin.base64"
		$a_01_3 = {54 65 78 74 20 3d 20 62 61 73 65 36 34 } //1 Text = base64
		$a_01_4 = {42 61 73 65 36 34 44 65 63 6f 64 65 20 3d 20 78 6d 6c 4e 6f 64 65 2e 6e 6f 64 65 54 79 70 65 64 56 61 6c 75 65 } //1 Base64Decode = xmlNode.nodeTypedValue
		$a_01_5 = {64 65 63 44 61 74 61 20 3d 20 42 61 73 65 36 34 44 65 63 6f 64 65 28 64 61 74 61 29 } //1 decData = Base64Decode(data)
		$a_01_6 = {73 74 72 50 61 74 68 20 3d 20 73 74 72 50 61 74 68 20 26 20 43 68 72 28 28 64 65 63 44 61 74 61 28 69 6e 78 29 20 58 6f 72 20 33 37 29 20 2b 20 31 33 34 20 2d 20 32 35 36 29 } //1 strPath = strPath & Chr((decData(inx) Xor 37) + 134 - 256)
		$a_01_7 = {28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 54 65 78 74 20 42 6f 78 20 33 22 29 } //1 (ActiveDocument.Shapes("Text Box 3")
		$a_01_8 = {28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 54 65 78 74 20 42 6f 78 20 34 22 29 } //1 (ActiveDocument.Shapes("Text Box 4")
		$a_01_9 = {28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 54 65 78 74 20 42 6f 78 20 35 22 29 } //1 (ActiveDocument.Shapes("Text Box 5")
		$a_01_10 = {28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 54 65 78 74 20 42 6f 78 20 36 22 29 } //1 (ActiveDocument.Shapes("Text Box 6")
		$a_01_11 = {6f 62 6a 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 74 72 4f 62 6a 65 63 74 29 } //1 objShell = CreateObject(strObject)
		$a_01_12 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 73 74 72 41 72 67 6d 65 6e 74 } //1 objShell.Run strArgment
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}