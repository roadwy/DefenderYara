
rule TrojanDownloader_O97M_Donoff_MXIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("WScript.Shell")
		$a_01_1 = {57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 50 72 69 6e 74 68 6f 6f 64 22 29 } //1 WshShell.SpecialFolders("Printhood")
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6d 69 63 72 6f 73 6f 66 74 2e 78 6d 6c 68 74 74 70 22 29 } //1 CreateObject("microsoft.xmlhttp")
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Shell.Application")
		$a_01_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 61 64 6f 64 62 2e 73 74 72 65 61 6d 22 29 } //1 CreateObject("adodb.stream")
		$a_01_5 = {4b 48 55 75 67 69 67 66 75 79 64 44 54 4a 6b 28 30 29 20 3d 20 32 33 33 } //1 KHUugigfuydDTJk(0) = 233
		$a_01_6 = {4b 48 55 75 67 69 67 66 75 79 64 44 54 4a 6b 28 31 29 20 3d 20 31 33 39 } //1 KHUugigfuydDTJk(1) = 139
		$a_01_7 = {4b 48 55 75 67 69 67 66 75 79 64 44 54 4a 6b 28 32 31 38 33 29 } //1 KHUugigfuydDTJk(2183)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}