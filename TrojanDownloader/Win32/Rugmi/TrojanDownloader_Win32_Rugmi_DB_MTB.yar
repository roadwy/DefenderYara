
rule TrojanDownloader_Win32_Rugmi_DB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b f3 8b e8 0f af 7c 24 ?? 0f b6 04 16 03 f8 46 3b f5 72 90 09 04 00 8b 54 24 } //1
		$a_03_1 = {8a 08 88 4d ?? 8b 55 ?? 0f af 55 ?? 0f b6 45 ?? 03 d0 89 55 ?? eb 90 09 06 00 8b 45 ?? 03 45 } //1
		$a_03_2 = {8a 00 88 45 ?? 8b 45 ?? 0f af 45 ?? 0f b6 4d ?? 03 c1 89 45 ?? eb 90 09 06 00 8b 45 ?? 03 45 } //1
		$a_03_3 = {0f 1f 40 00 0f af 54 24 ?? 0f b6 04 3e 46 03 d0 3b f1 72 } //1
		$a_01_4 = {90 90 90 0f af d8 0f b6 4d 00 01 cb 45 4e 75 f3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}