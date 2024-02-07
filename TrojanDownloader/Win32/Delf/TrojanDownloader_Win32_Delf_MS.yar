
rule TrojanDownloader_Win32_Delf_MS{
	meta:
		description = "TrojanDownloader:Win32/Delf.MS,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {5c 44 65 62 75 67 73 5c 6c 73 61 73 73 30 30 2e 65 78 65 } //02 00  \Debugs\lsass00.exe
		$a_01_1 = {37 35 32 37 34 35 37 34 34 37 34 35 37 34 35 37 38 39 38 31 32 37 34 36 37 35 32 37 35 32 } //01 00  752745744745745789812746752752
		$a_01_2 = {48 54 54 50 2f 31 2e 30 20 32 30 30 20 4f 4b } //00 00  HTTP/1.0 200 OK
	condition:
		any of ($a_*)
 
}