
rule TrojanDownloader_Win32_Agent_ZDK{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDK,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 63 30 72 72 75 70 74 65 64 2e 63 6f 6d } //0a 00 
		$a_01_1 = {89 4c 24 04 b8 03 01 00 00 89 14 24 88 9d c8 fd ff ff bb 04 01 00 00 89 44 24 08 e8 d8 1a 00 00 89 5c 24 04 8d 9d c8 fd ff ff 89 1c 24 e8 26 1d 00 00 83 ec 08 89 5c 24 08 89 7c 24 04 bf 08 91 40 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Agent_ZDK_2{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 8d 4d e8 66 ba 2d 43 b8 90 01 04 e8 90 01 04 8b 45 e8 e8 90 01 04 50 8d 4d e4 66 ba 2d 43 b8 90 01 04 e8 3a fe ff ff 8b 45 e4 e8 90 01 04 50 6a 00 e8 90 01 04 6a 05 68 90 01 04 e8 90 01 04 33 c0 5a 59 59 64 89 10 68 90 00 } //01 00 
		$a_00_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 69 6d 67 6c 6f 67 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Agent_ZDK_3{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDK,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 76 00 69 00 64 00 61 00 72 00 65 00 61 00 6c 00 32 00 30 00 31 00 30 00 2e 00 70 00 69 00 73 00 65 00 6d 00 2e 00 73 00 75 00 2f 00 69 00 6d 00 67 00 6c 00 6f 00 67 00 2e 00 65 00 78 00 65 00 } //0a 00 
		$a_01_1 = {c7 45 fc 07 00 00 00 68 1c 2c 40 00 e8 f1 06 00 00 0f bf c8 85 c9 75 48 c7 45 fc 08 00 00 00 ba 1c 2c 40 00 8d 4d 90 ff 15 98 10 40 00 } //00 00 
	condition:
		any of ($a_*)
 
}