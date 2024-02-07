
rule TrojanDownloader_Win32_Delf_RAS{
	meta:
		description = "TrojanDownloader:Win32/Delf.RAS,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {84 c0 74 0c 6a 00 68 90 01 02 44 00 e8 90 01 02 fb ff e8 90 01 02 fb ff 43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 50 72 6f 67 72 61 6d 61 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 65 78 70 6c 6f 72 65 2e 65 78 65 90 00 } //01 00 
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_00_2 = {57 69 6e 45 78 65 63 } //00 00  WinExec
	condition:
		any of ($a_*)
 
}