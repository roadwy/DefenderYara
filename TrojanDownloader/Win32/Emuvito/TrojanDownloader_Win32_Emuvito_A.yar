
rule TrojanDownloader_Win32_Emuvito_A{
	meta:
		description = "TrojanDownloader:Win32/Emuvito.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 3b 58 75 f8 80 7b 01 58 75 f2 80 7b 02 58 75 ec 89 1d 90 01 02 42 00 a1 90 01 02 42 00 83 78 14 00 0f 85 7b 03 00 00 a1 90 01 02 42 00 8b 58 04 90 00 } //01 00 
		$a_03_1 = {8a 10 80 f2 90 01 01 88 10 43 40 83 fb 0d 75 f2 90 00 } //01 00 
		$a_03_2 = {8b d8 8a 83 90 01 02 42 00 e8 90 01 03 ff 3c 45 0f 84 dd 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}