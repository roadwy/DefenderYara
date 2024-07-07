
rule TrojanDownloader_Win32_Small_DBB{
	meta:
		description = "TrojanDownloader:Win32/Small.DBB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 61 2e 65 78 65 } //1 C:\a.exe
		$a_03_1 = {68 74 74 70 3a 2f 2f 79 67 73 6f 6e 64 68 65 6b 73 2e 69 6e 66 6f 2f 63 2f 90 01 04 2f 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 90 00 } //1
		$a_00_2 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_00_3 = {8b ec 6a 00 ff 15 08 31 40 00 6a 00 6a 00 6a 00 6a 04 6a 02 6a 00 6a 00 6a ff 6a 00 ff 15 04 31 40 00 6a 00 6a 2e 68 9f 30 40 00 68 a8 30 40 00 e8 15 00 00 00 6a 05 68 9f 30 40 00 ff 15 e8 30 40 00 6a 00 ff 15 e4 30 40 00 55 8b ec 83 c4 d4 eb 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}