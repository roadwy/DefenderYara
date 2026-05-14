
rule Trojan_O97M_Downloader_BP_MSR{
	meta:
		description = "Trojan:O97M/Downloader.BP!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 63 72 69 70 74 55 72 6c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 63 6c 6f 75 64 2d 73 74 6f 72 61 67 65 2e 61 72 74 2f 64 6f 63 2f 59 31 2e 70 73 31 22 } //1 scriptUrl = "https://cloud-storage.art/doc/Y1.ps1"
		$a_01_1 = {74 65 6d 70 44 69 72 20 3d 20 22 43 3a 5c 54 65 6d 70 22 } //1 tempDir = "C:\Temp"
		$a_01_2 = {73 63 72 69 70 74 50 61 74 68 20 3d 20 74 65 6d 70 44 69 72 20 26 20 22 5c 59 31 2e 70 73 31 22 } //1 scriptPath = tempDir & "\Y1.ps1"
		$a_01_3 = {73 68 65 6c 6c 2e 52 75 6e 20 22 50 6f 77 65 72 53 68 65 6c 6c 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 52 65 6d 6f 74 65 53 69 67 6e 65 64 20 2d 46 69 6c 65 20 22 22 22 20 26 20 73 63 72 69 70 74 50 61 74 68 20 26 20 22 22 22 22 2c 20 30 2c 20 54 72 75 65 } //1 shell.Run "PowerShell -NoProfile -ExecutionPolicy RemoteSigned -File """ & scriptPath & """", 0, True
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}