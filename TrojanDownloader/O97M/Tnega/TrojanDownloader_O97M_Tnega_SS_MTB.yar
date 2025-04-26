
rule TrojanDownloader_O97M_Tnega_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Tnega.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 2e 46 69 6c 65 45 78 69 73 74 73 28 73 7a 46 69 6c 65 29 } //1 CreateObject("Scripting.FileSystemObject").FileExists(szFile)
		$a_01_1 = {53 65 74 20 6f 4e 6f 64 65 20 3d 20 6f 58 4d 4c 2e 43 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 61 73 65 36 34 22 29 } //1 Set oNode = oXML.CreateElement("base64")
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 50 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 4d 69 63 72 6f 73 6f 66 74 5c 4e 6f 74 69 63 65 } //1 = Environ("UserProfile") & "\AppData\Local\Microsoft\Notice
		$a_01_3 = {64 6c 6c 50 61 74 68 20 3d 20 77 6f 72 6b 44 69 72 20 26 20 22 5c 22 20 26 20 62 69 6e 4e 61 6d 65 } //1 dllPath = workDir & "\" & binName
		$a_01_4 = {62 69 6e 4e 61 6d 65 20 3d 20 22 77 73 64 74 73 2e 64 62 } //1 binName = "wsdts.db
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}