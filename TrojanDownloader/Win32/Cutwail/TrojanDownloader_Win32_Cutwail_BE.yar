
rule TrojanDownloader_Win32_Cutwail_BE{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f9 75 0f 95 c2 8b 45 0c 88 10 8b 4d 08 0f be 51 51 33 c0 83 fa 7a 0f 94 c0 } //1
		$a_01_1 = {8b 8d c0 fc ff ff 03 48 28 89 8d d8 fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Cutwail_BE_2{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 05 01 01 01 01 51 8a c8 d3 c0 59 51 8a c8 eb 08 00 00 00 00 00 00 00 00 d3 c0 59 05 01 01 01 00 05 01 01 01 01 81 f9 35 7c 01 00 72 03 89 45 f0 } //1
		$a_01_1 = {78 76 72 66 69 65 72 2e 64 6c 6c 00 42 65 67 69 6e 53 65 61 72 63 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Cutwail_BE_3{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BE,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 6a 18 ff 35 ?? ?? ?? ?? 90 17 03 01 06 02 e8 b8 ?? ?? ?? ?? ff d0 ff d7 } //10
		$a_03_1 = {81 c6 ca 01 00 00 (90 09 11 00|90 09 0e 00) b9 90 17 03 02 02 02 00 24 e2 25 ca 29 00 00 8b } //1
		$a_03_2 = {81 c6 ca 01 00 00 90 09 0e 00 b9 00 ?? ?? ?? c1 e9 02 } //1
		$a_03_3 = {ac 32 c3 aa f7 c1 01 00 00 00 74 ?? 85 c0 60 } //1
		$a_01_4 = {ad 33 85 f4 fc ff ff ab e2 db b8 00 } //1
		$a_03_5 = {ff ff ad 33 85 ?? ?? ff ff ab e2 90 09 0a 00 05 ?? ?? ?? ?? 50 8f 85 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=12
 
}