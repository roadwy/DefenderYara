
rule TrojanDownloader_Win32_Small_WX{
	meta:
		description = "TrojanDownloader:Win32/Small.WX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {55 68 80 00 00 00 6a 02 55 6a 04 68 ff 01 1f 00 53 ff 15 90 01 04 8b d8 8d 44 24 20 55 50 57 56 53 89 6c 24 34 ff 15 90 00 } //02 00 
		$a_03_1 = {b8 00 00 00 80 be 02 00 00 00 bd 04 00 00 00 eb 0f b8 00 00 00 c0 be 04 00 00 00 bd 06 00 00 00 6a 00 6a 00 6a 03 6a 00 6a 01 50 8b 44 24 2c 50 ff 15 90 01 04 8b f8 83 ff ff 90 00 } //01 00 
		$a_01_2 = {5c 64 6f 77 6e 2e 74 78 74 } //01 00  \down.txt
		$a_01_3 = {63 6c 63 6f 75 6e 74 2f 63 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d } //01 00  clcount/count.asp?mac=
		$a_01_4 = {47 6c 6f 62 61 6c 5c 45 56 45 4e 54 5f 62 6f 73 73 69 73 72 75 6e 69 6e 67 } //01 00  Global\EVENT_bossisruning
		$a_01_5 = {47 6c 6f 62 61 6c 5c 45 56 45 4e 54 5f 44 4f 47 5f 44 4f 47 5f 58 58 58 } //00 00  Global\EVENT_DOG_DOG_XXX
	condition:
		any of ($a_*)
 
}