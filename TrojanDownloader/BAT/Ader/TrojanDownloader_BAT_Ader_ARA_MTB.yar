
rule TrojanDownloader_BAT_Ader_ARA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 9c 06 17 58 0a 06 08 8e 69 32 e6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Ader_ARA_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f 90 01 03 0a 06 17 58 0a 06 08 8e 69 32 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Ader_ARA_MTB_3{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 15 00 06 08 07 09 91 06 08 91 61 28 90 01 03 0a 9c 00 09 17 58 0d 09 07 8e 69 fe 04 13 05 11 05 2d df 00 08 17 58 0c 08 06 8e 69 fe 04 13 05 11 05 2d c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Ader_ARA_MTB_4{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {70 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 8c 90 00 } //02 00 
		$a_03_1 = {0a 0a 00 07 17 58 0b 07 02 6f 90 01 03 0a fe 04 0c 08 2d c1 06 0d 2b 00 09 2a 90 00 } //02 00 
		$a_01_2 = {51 00 7a 00 70 00 63 00 58 00 46 00 64 00 70 00 62 00 6d 00 52 00 76 00 64 00 33 00 4e 00 63 00 58 00 45 00 31 00 70 00 59 00 33 00 4a 00 76 00 63 00 32 00 39 00 6d 00 64 00 43 00 35 00 4f 00 52 00 56 00 52 00 63 00 58 00 45 00 5a 00 79 00 59 00 57 00 31 00 6c 00 64 00 32 00 39 00 79 00 61 00 31 00 78 00 63 00 64 00 6a 00 51 00 75 00 4d 00 43 00 34 00 7a 00 4d 00 44 00 4d 00 78 00 4f 00 56 00 78 00 63 00 55 00 6d 00 56 00 6e 00 51 00 58 00 4e 00 74 00 4c 00 6d 00 56 00 34 00 5a 00 51 00 3d 00 3d 00 } //00 00  QzpcXFdpbmRvd3NcXE1pY3Jvc29mdC5ORVRcXEZyYW1ld29ya1xcdjQuMC4zMDMxOVxcUmVnQXNtLmV4ZQ==
	condition:
		any of ($a_*)
 
}