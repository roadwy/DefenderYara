
rule TrojanDownloader_Win32_Argnot_A{
	meta:
		description = "TrojanDownloader:Win32/Argnot.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {74 0b 8b 45 e4 83 e8 04 8b 00 89 45 e4 8b 45 e4 85 c0 7e 40 89 45 e8 c7 45 f0 01 00 00 00 8d 45 e0 ba 90 01 04 8b 4d f4 66 8b 54 4a fe 8b 4d fc 8b 5d f0 66 8b 4c 59 fe 66 33 d1 e8 90 01 04 8b 55 e0 8d 45 ec 90 00 } //01 00 
		$a_00_1 = {61 00 76 00 73 00 63 00 68 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  avsche.exe
		$a_00_2 = {45 00 41 00 53 00 65 00 6e 00 64 00 2e 00 64 00 6c 00 6c 00 } //01 00  EASend.dll
		$a_00_3 = {6e 00 6f 00 74 00 61 00 2e 00 72 00 61 00 72 00 } //00 00  nota.rar
		$a_00_4 = {5d 04 00 00 59 a3 02 80 5c 21 } //00 00 
	condition:
		any of ($a_*)
 
}