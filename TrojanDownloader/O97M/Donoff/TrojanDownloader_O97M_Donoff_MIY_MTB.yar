
rule TrojanDownloader_O97M_Donoff_MIY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MIY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,14 00 14 00 0a 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //2 CreateObject("wscript.shell")
		$a_01_1 = {66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67 20 26 20 22 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6d 61 69 6e 2e 68 74 61 } //2 frm.CommandButton1.Tag & " c:\users\public\main.hta
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 79 73 74 65 6d 2e 54 65 78 74 2e 53 74 72 69 6e 67 42 75 69 6c 64 65 72 22 29 } //2 CreateObject("System.Text.StringBuilder")
		$a_01_3 = {73 63 72 65 65 6e 4d 65 6d 6f 72 79 57 2e 72 65 73 69 7a 65 54 6f 28 31 2c 20 31 29 } //2 screenMemoryW.resizeTo(1, 1)
		$a_01_4 = {73 63 72 65 65 6e 4d 65 6d 6f 72 79 57 2e 6d 6f 76 65 54 6f 28 2d 31 30 30 2c 20 2d 31 30 30 29 } //2 screenMemoryW.moveTo(-100, -100)
		$a_01_5 = {75 66 66 65 72 20 3d 20 73 63 72 65 65 6e 53 69 7a 65 54 65 78 74 28 74 61 62 6c 65 56 61 72 69 61 62 6c 65 28 72 65 71 75 65 73 74 52 65 71 75 65 73 74 43 6f 75 6e 74 65 72 5b 30 5d 29 29 } //2 uffer = screenSizeText(tableVariable(requestRequestCounter[0]))
		$a_01_6 = {73 65 6c 65 63 74 4e 61 6d 65 73 70 61 63 65 2e 54 69 6d 65 6f 75 74 20 3d 20 36 30 30 30 30 } //2 selectNamespace.Timeout = 60000
		$a_01_7 = {4d 65 6d 6f 72 79 57 2e 63 6c 6f 73 65 } //2 MemoryW.close
		$a_01_8 = {73 77 61 70 56 62 54 61 62 6c 65 2e 54 6f 53 74 72 69 6e 67 } //2 swapVbTable.ToString
		$a_01_9 = {28 27 6d 73 73 63 72 69 70 74 63 6f 6e 74 72 6f 6c 2e 73 63 72 69 70 74 63 6f 6e 74 72 6f 6c 27 29 } //2 ('msscriptcontrol.scriptcontrol')
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2) >=20
 
}