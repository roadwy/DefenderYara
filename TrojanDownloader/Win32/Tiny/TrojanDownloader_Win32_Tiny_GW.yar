
rule TrojanDownloader_Win32_Tiny_GW{
	meta:
		description = "TrojanDownloader:Win32/Tiny.GW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 31 39 35 2e 32 32 35 2e 31 37 36 2e 33 34 2f 61 64 2f 90 01 04 2f 61 64 76 65 72 74 6f 6f 6c 2e 68 74 6d 6c 90 00 } //01 00 
		$a_00_1 = {63 3a 5c 55 6e 65 72 65 73 65 2e 65 78 65 } //01 00  c:\Unerese.exe
		$a_00_2 = {b8 00 30 40 00 bb 2d 30 40 00 e8 1e 00 00 00 6a 00 68 3c 30 40 00 6a 00 68 2d 30 40 00 6a 00 6a 00 e8 32 01 00 00 6a 00 e8 13 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}