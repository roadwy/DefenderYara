
rule TrojanDownloader_Win32_Delf_KK{
	meta:
		description = "TrojanDownloader:Win32/Delf.KK,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {7b 41 38 46 37 37 37 43 43 2d 43 36 41 46 2d 34 34 37 42 2d 41 36 31 31 2d 31 30 41 39 42 41 31 35 41 32 32 39 7d } //0a 00  {A8F777CC-C6AF-447B-A611-10A9BA15A229}
		$a_00_1 = {5c 57 69 6e 64 6f 77 73 5c 52 65 6c 6f 61 64 2e 64 6c 6c } //0a 00  \Windows\Reload.dll
		$a_00_2 = {5c 41 56 47 5c 41 56 47 39 5c 61 76 67 75 70 64 2e 64 6c 6c } //01 00  \AVG\AVG9\avgupd.dll
		$a_02_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 65 62 2d 65 73 74 2e 63 6f 6d 2f 90 02 08 2e 6a 70 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}