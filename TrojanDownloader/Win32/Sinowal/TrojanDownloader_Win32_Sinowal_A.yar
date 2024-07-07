
rule TrojanDownloader_Win32_Sinowal_A{
	meta:
		description = "TrojanDownloader:Win32/Sinowal.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 c9 92 07 00 00 83 f1 50 90 02 10 c1 f9 0a 90 00 } //1
		$a_03_1 = {8a 02 88 45 fb 90 02 10 8a 55 fb 88 11 8b 45 90 01 01 05 90 01 04 89 45 90 01 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Sinowal_A_2{
	meta:
		description = "TrojanDownloader:Win32/Sinowal.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 c9 92 07 00 00 83 f1 50 90 02 10 c1 f9 0a 90 00 } //1
		$a_03_1 = {8a 02 88 45 fb 90 02 10 8a 55 fb 88 11 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Sinowal_A_3{
	meta:
		description = "TrojanDownloader:Win32/Sinowal.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 1f 8b 55 90 01 01 03 55 90 01 01 0f be 02 83 c0 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 88 01 8b 55 90 01 01 83 c2 01 89 55 90 01 01 eb d4 90 00 } //1
		$a_03_1 = {75 09 c7 45 fc fe ff ff ff eb 71 68 90 01 04 8b 4d 90 01 01 51 ff 15 90 01 04 89 45 90 01 01 83 7d 90 01 01 00 74 38 90 00 } //1
		$a_01_2 = {e9 34 01 00 00 0f b7 45 14 3d bb 01 00 00 75 0c 8b 4d f8 81 c9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}