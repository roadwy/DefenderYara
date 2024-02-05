
rule TrojanDownloader_Win32_Dadobra_BN{
	meta:
		description = "TrojanDownloader:Win32/Dadobra.BN,SIGNATURE_TYPE_PEHSTR,0c 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {e8 1e ed ff ff 8b 55 f4 b8 c4 a4 41 00 e8 c5 99 fe ff 85 c0 7f 4c 8d 45 e8 8b d3 e8 7b 96 fe ff 8b 45 e8 8d 55 ec e8 f8 ec ff ff 8b 55 ec b8 d8 a4 41 00 e8 9f 99 fe ff 85 c0 7f 26 8d 45 e0 8b d3 e8 55 96 fe ff 8b 45 e0 8d 55 e4 e8 d2 ec ff ff 8b 55 e4 b8 ec a4 41 00 e8 79 99 fe ff 85 c0 7e 0b 33 db 6a 16 e8 58 aa fe ff eb 09 53 ff 15 8c c7 41 00 } //01 00 
		$a_01_1 = {53 65 74 74 69 6e 67 73 5c 7b 46 43 41 44 44 43 31 34 2d 42 44 34 36 2d 34 30 38 41 2d 39 38 34 32 2d 43 44 42 45 31 43 36 44 33 37 45 42 } //01 00 
		$a_01_2 = {6d 73 61 70 70 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}