
rule TrojanDownloader_Win32_Pingbed_A{
	meta:
		description = "TrojanDownloader:Win32/Pingbed.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 01 6a 10 57 68 90 01 02 00 00 56 56 b9 90 01 04 e8 90 01 04 b9 90 01 04 e8 90 01 04 6a 10 57 90 00 } //01 00 
		$a_03_1 = {68 e8 03 00 00 8b f0 ff 15 90 01 04 3b 90 01 01 76 90 01 01 56 90 01 01 68 ff 0f 1f 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Pingbed_A_2{
	meta:
		description = "TrojanDownloader:Win32/Pingbed.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 44 31 ff 32 04 31 8a d0 c0 ea 03 c0 e0 05 0a d0 88 14 31 49 75 e9 } //01 00 
		$a_01_1 = {8a 06 32 44 24 0c 8a c8 c0 e9 03 c0 e0 05 0a c8 88 0e 5e } //01 00 
		$a_01_2 = {8a 06 5f 8a c8 c0 e1 03 c0 e8 05 0a c8 32 4c 24 10 39 7c 24 14 88 0e } //01 00 
		$a_01_3 = {8a 14 37 8d 04 37 8a ca c0 e1 03 c0 ea 05 0a ca 88 08 8a 54 37 ff 32 d1 47 3b 7c 24 14 88 10 72 df } //00 00 
	condition:
		any of ($a_*)
 
}