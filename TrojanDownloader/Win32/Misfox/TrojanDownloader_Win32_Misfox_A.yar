
rule TrojanDownloader_Win32_Misfox_A{
	meta:
		description = "TrojanDownloader:Win32/Misfox.A,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {eb 09 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1 } //0a 00 
		$a_01_1 = {8a 01 3c 61 7c 15 3c 7a 7f 11 0f be c0 83 e8 54 6a 1a 99 5f f7 ff 80 c2 61 eb 17 3c 41 7c 15 3c 5a 7f 11 0f be c0 83 e8 34 6a 1a 99 5f f7 ff 80 c2 41 88 11 41 80 39 00 75 c6 } //01 00 
		$a_00_2 = {59 3a 5c 00 58 3a 5c 00 5a 3a 5c 00 48 3a 5c 00 47 3a 5c 00 46 3a 5c 00 45 3a 5c 00 44 3a 5c 00 43 3a 5c 00 } //01 00 
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 2f 90 00 } //01 00 
		$a_00_4 = {62 69 6e 67 2e 63 6f 6d } //01 00 
		$a_00_5 = {4e 4a 42 23 } //00 00 
	condition:
		any of ($a_*)
 
}