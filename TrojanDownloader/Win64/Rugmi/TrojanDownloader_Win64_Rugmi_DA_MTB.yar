
rule TrojanDownloader_Win64_Rugmi_DA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 63 44 24 24 48 8b 4c 24 40 0f b7 0c 41 e8 ?? ?? ?? ?? 66 89 44 24 20 69 44 24 28 3f 00 01 00 0f b7 4c 24 20 03 c1 89 44 24 28 eb } //1
		$a_03_1 = {0f b7 00 0f b7 c0 89 c1 e8 ?? ?? ?? ?? 66 89 45 f2 8b 45 fc 69 d0 3f 00 01 00 0f b7 45 f2 01 d0 89 45 fc 83 45 f8 01 eb } //1
		$a_03_2 = {41 0f b7 08 8d 41 bf 66 83 f8 19 77 ?? 66 83 c1 20 45 69 c9 3f 00 01 00 49 83 c0 02 0f b7 d1 44 03 ca 49 83 ea 01 75 } //1
		$a_03_3 = {0f b7 02 8d 48 bf 66 83 f9 19 77 ?? 66 83 c0 20 45 69 c0 3f 00 01 00 48 83 c2 02 0f b7 c8 44 03 c1 49 83 e9 01 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}