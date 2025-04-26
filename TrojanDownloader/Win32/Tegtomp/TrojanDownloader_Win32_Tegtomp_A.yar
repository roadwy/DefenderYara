
rule TrojanDownloader_Win32_Tegtomp_A{
	meta:
		description = "TrojanDownloader:Win32/Tegtomp.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 ec 8c 04 00 00 8d 6c 24 fc a1 ?? ?? ?? 00 33 c5 89 85 8c 04 00 00 6a 20 b8 } //1
		$a_01_1 = {8b 9d 0c 01 00 00 83 65 f0 00 8d 7d d0 89 5d ec e8 } //1
		$a_01_2 = {33 f6 89 75 fc 56 6a 2d 8b cf 89 7d ec 89 75 f0 e8 7c 5b fd ff } //1
		$a_03_3 = {89 75 fc c7 45 f0 01 00 00 00 8a 9e ?? ?? ?? 00 56 8b cf 80 f3 49 e8 } //1
		$a_03_4 = {83 c4 18 c7 07 44 00 00 00 38 5d 10 74 ?? 33 c0 c7 46 4c 01 00 00 00 66 89 46 50 8b 45 cc 83 78 18 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}