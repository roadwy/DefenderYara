
rule TrojanDownloader_Win32_Shen_A{
	meta:
		description = "TrojanDownloader:Win32/Shen.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //01 00  Microsoft Visual C++ Runtime Library
		$a_00_1 = {7a 6e 35 62 2e 63 6f 6d 2f 67 67 62 68 2f 67 67 62 68 2e 63 67 69 3f } //01 00  zn5b.com/ggbh/ggbh.cgi?
		$a_00_2 = {63 68 65 6e 7a 6e 77 62 2e 65 78 65 } //01 00  chenznwb.exe
		$a_00_3 = {64 6d 73 68 65 6c 6c 2e 64 6c 6c } //01 00  dmshell.dll
		$a_00_4 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //01 00  CreateMutexW
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //00 00  InternetOpenUrlA
	condition:
		any of ($a_*)
 
}