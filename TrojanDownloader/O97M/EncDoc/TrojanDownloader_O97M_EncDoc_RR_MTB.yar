
rule TrojanDownloader_O97M_EncDoc_RR_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 6f 62 6a 58 4d 4c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 22 29 } //1 Set objXML = CreateObject("MSXML2.DOMDocument")
		$a_01_1 = {53 65 74 20 6f 62 6a 4e 6f 64 65 20 3d 20 6f 62 6a 58 4d 4c 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //1 Set objNode = objXML.createElement("b64")
		$a_01_2 = {6f 62 6a 4e 6f 64 65 2e 44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //1 objNode.DataType = "bin.base64"
		$a_01_3 = {46 75 6e 63 74 69 6f 6e 20 44 65 63 6f 64 65 42 61 73 65 36 34 28 42 79 56 61 6c 20 73 74 72 44 61 74 61 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 42 79 74 65 28 29 } //1 Function DecodeBase64(ByVal strData As String) As Byte()
		$a_01_4 = {73 74 72 54 65 6d 70 50 61 74 68 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 4e 41 4d 45 22 29 20 26 20 22 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 42 41 4d 73 67 42 6f 78 2e 65 78 65 22 } //1 strTempPath = "C:\Users\" & Environ("USERNAME") & "\Documents\VBAMsgBox.exe"
		$a_01_5 = {4f 70 65 6e 20 73 74 72 54 65 6d 70 50 61 74 68 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 20 23 } //1 Open strTempPath For Binary As #
		$a_01_6 = {50 75 74 20 23 31 2c 20 31 2c 20 44 65 63 6f 64 65 42 61 73 65 36 34 28 73 74 72 44 61 74 61 29 } //1 Put #1, 1, DecodeBase64(strData)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}