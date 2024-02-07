
rule TrojanDownloader_Win32_Delfobfus_A{
	meta:
		description = "TrojanDownloader:Win32/Delfobfus.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 89 45 90 01 01 83 7d 90 01 01 00 75 0a 33 c0 89 45 90 01 01 e9 90 01 02 00 00 90 00 } //01 00 
		$a_02_1 = {8d 45 d0 8a 55 fb 8b 4d fc 8b 5d e8 8a 4c 19 ff 32 d1 e8 90 01 03 ff 8b 55 d0 8d 45 f0 e8 90 01 03 ff ff 45 e8 ff 4d dc 75 d6 90 00 } //02 00 
		$a_02_2 = {33 c0 89 45 90 01 01 83 7d 90 01 01 00 75 0a 33 c0 89 45 90 01 01 e9 90 01 02 00 00 e8 90 01 03 ff 85 c0 0f 84 90 01 02 00 00 e8 90 01 03 ff 85 c0 0f 84 90 01 02 00 00 e8 90 01 03 ff 85 c0 0f 84 90 01 02 00 00 e8 90 01 03 ff 85 c0 0f 84 90 01 02 00 00 e8 90 01 03 ff 85 c0 0f 84 90 01 02 00 00 e8 90 01 03 ff 85 c0 0f 84 90 01 02 00 00 e8 90 01 03 ff 85 c0 0f 84 90 01 02 00 00 e8 90 01 03 ff 90 00 } //0a 00 
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00  SOFTWARE\Borland\Delphi\RTL
	condition:
		any of ($a_*)
 
}