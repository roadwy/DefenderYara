
rule TrojanDownloader_Win32_Rugmi_HNR_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 51 83 65 fc 00 83 65 f8 00 33 c0 40 74 2e 8b 45 fc 8b 4d 08 0f b7 04 41 83 f8 5c 75 06 8b 45 fc 89 45 f8 8b 45 fc 8b 4d 08 0f b7 04 41 85 c0 75 02 eb 09 8b 45 fc 40 89 45 fc eb cd 8b 45 f8 8b 4d 08 8d 44 41 02 8b e5 5d c3 } //5
		$a_03_1 = {59 6a 00 ff 15 90 09 17 00 [0-10] 8b 00 03 45 ?? 89 45 ?? 8b 45 ?? 89 45 ?? ff 75 ?? ff 55 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}