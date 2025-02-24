
rule TrojanDownloader_Win32_Satacom_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Satacom.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 04 39 88 04 3b 47 3b 7d 18 72 cd } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule TrojanDownloader_Win32_Satacom_ARA_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/Satacom.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe c2 0f b6 d2 8b 4c ?? ?? 8d 04 0b 0f b6 d8 8b 44 ?? ?? 89 44 ?? ?? 89 4c ?? ?? 02 c8 0f b6 c1 8b 4d f8 8a 44 ?? ?? 30 04 ?? ?? 3b ?? fc 7c d0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule TrojanDownloader_Win32_Satacom_ARA_MTB_3{
	meta:
		description = "TrojanDownloader:Win32/Satacom.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 8b 4d dc 03 45 c8 33 d2 23 45 e0 d3 e0 b9 08 00 00 00 8a 55 eb 2b 4d dc d3 fa 03 c2 c1 e0 08 8d 04 40 03 c0 03 45 f0 05 6c 0e 00 00 83 fb 07 7c 34 8b d7 2b d6 89 55 a4 8b 4d a4 3b 4d bc 72 06 8b 55 bc 01 55 a4 8b 4d c0 8b 55 a4 8a 0c 11 88 4d ab 8d 95 ?? ?? ?? ?? 8a 4d ab e8 ?? ?? ?? ?? 88 45 eb eb 0e 8d 95 ?? ?? ?? ?? e8 ?? ?? ?? ?? 88 45 eb 8b 45 98 8a 4d eb 88 08 ff 45 ec ff 45 98 8b 45 c4 3b 45 bc 73 03 ff 45 c4 8b 55 c0 8a 4d eb 88 0c 3a 47 3b 7d bc 75 02 } //1
		$a_01_1 = {43 68 65 79 65 6e 6e 65 31 22 30 } //1 Cheyenne1"0
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}