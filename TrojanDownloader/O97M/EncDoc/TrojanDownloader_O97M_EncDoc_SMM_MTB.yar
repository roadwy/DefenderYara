
rule TrojanDownloader_O97M_EncDoc_SMM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SMM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 CreateObject("Scripting.FileSystemObject")
		$a_01_1 = {6f 62 6a 46 53 4f 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 73 74 72 46 69 6c 65 6e 61 6d 65 2c 20 32 2c 20 54 72 75 65 29 } //1 objFSO.OpenTextFile(strFilename, 2, True)
		$a_01_2 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 22 20 26 20 72 65 61 6c 50 61 74 68 } //1 Environ("TEMP") & "\" & realPath
		$a_01_3 = {45 78 65 63 75 74 65 43 6d 64 41 73 79 6e 63 20 73 74 72 43 6d 64 } //1 ExecuteCmdAsync strCmd
		$a_01_4 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_5 = {3d 20 22 78 73 71 66 67 2e 65 78 65 22 } //1 = "xsqfg.exe"
		$a_01_6 = {3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //1 = objWMIService.Get("Win32_ProcessStartup")
		$a_01_7 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}