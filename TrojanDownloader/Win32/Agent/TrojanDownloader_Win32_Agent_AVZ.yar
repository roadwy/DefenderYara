
rule TrojanDownloader_Win32_Agent_AVZ{
	meta:
		description = "TrojanDownloader:Win32/Agent.AVZ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_1 = {22 25 73 22 20 2f 56 45 52 59 53 49 4c 45 4e 54 } //1 "%s" /VERYSILENT
		$a_00_2 = {2f 52 45 47 49 53 54 52 59 46 49 58 2e 45 58 45 } //1 /REGISTRYFIX.EXE
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_4 = {63 3a 5c 52 50 43 49 6e 73 74 61 6c 6c 5c 52 65 6c 65 61 73 65 5c 52 50 43 49 6e 73 74 61 6c 6c 2e 70 64 62 } //1 c:\RPCInstall\Release\RPCInstall.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}