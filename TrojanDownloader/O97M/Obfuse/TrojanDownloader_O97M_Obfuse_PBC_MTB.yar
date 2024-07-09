
rule TrojanDownloader_O97M_Obfuse_PBC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 41 54 41 } //1 = Environ("AppDATA
		$a_03_1 = {34 74 6f 70 2e 69 6f 2f [0-0f] 2e 6a 70 67 90 0a 3c 00 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 62 2e 74 6f 70 } //1
		$a_00_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c } //1 = CreateObject("WScript.Shell
		$a_00_3 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 22 61 76 67 2e 76 62 65 } //1 objShell.Run "avg.vbe
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_PBC_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 44 61 74 65 44 69 66 66 28 22 73 22 2c 20 22 30 31 2f 30 31 2f 31 39 37 30 20 30 30 3a 30 30 3a 30 30 22 2c 20 4e 6f 77 28 29 29 } //1 = DateDiff("s", "01/01/1970 00:00:00", Now())
		$a_03_1 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 20 28 74 73 20 26 20 22 2e [0-08] 2e 63 61 63 68 65 64 6e 73 2e 69 6f 22 29 } //1
		$a_01_2 = {2e 46 69 6c 65 45 78 69 73 74 73 28 63 6f 70 20 2b 20 22 5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 46 67 73 5c 46 69 6c 65 53 79 6e 63 53 68 65 6c 6c 36 34 2e 64 6c 6c 22 29 } //1 .FileExists(cop + "\Microsoft\EdgeFgs\FileSyncShell64.dll")
		$a_01_3 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 63 6f 70 20 2b 20 22 5c 54 65 6d 70 5c 77 63 74 22 20 2b 20 43 53 74 72 28 77 63 74 29 20 2b 20 22 2e 74 6d 70 22 2c 20 32 } //1 .SaveToFile cop + "\Temp\wct" + CStr(wct) + ".tmp", 2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}