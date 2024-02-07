
rule TrojanDownloader_Win32_Cadux_B{
	meta:
		description = "TrojanDownloader:Win32/Cadux.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 3a 00 5c 00 4d 00 61 00 73 00 74 00 65 00 72 00 5c 00 62 00 62 00 5f 00 73 00 6f 00 66 00 74 00 5c 00 6e 00 65 00 77 00 5c 00 62 00 62 00 5f 00 62 00 68 00 6f 00 5c 00 56 00 42 00 42 00 48 00 4f 00 2e 00 76 00 62 00 70 00 00 00 } //01 00 
		$a_01_1 = {44 3a 5c 4d 61 73 74 65 72 5c 55 4e 49 5f 53 4f 46 54 5c 41 44 57 41 52 41 5c 62 68 6f 5c 76 62 62 68 6f 2e 74 6c 62 00 } //01 00 
		$a_01_2 = {67 65 74 73 6e 33 32 2e 64 6c 6c 00 } //00 00  敧獴㍮⸲汤l
	condition:
		any of ($a_*)
 
}