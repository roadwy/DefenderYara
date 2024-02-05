
rule TrojanDownloader_Win32_Dold_A{
	meta:
		description = "TrojanDownloader:Win32/Dold.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b7 fb 8b 55 00 0f b6 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 0f af 35 90 01 04 66 03 35 90 01 04 43 66 ff 4c 24 04 75 c0 90 00 } //01 00 
		$a_00_1 = {6f 00 4a 00 33 00 46 00 6b 00 47 00 30 00 61 00 6a 00 6f 00 6f 00 50 00 50 00 6c 00 74 00 74 00 4e 00 54 00 6b 00 38 00 46 00 2f 00 32 00 57 00 6b 00 2b 00 42 00 5a 00 6d 00 6a 00 75 00 2b 00 79 00 43 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}