
rule TrojanDownloader_Win32_Andromeda_SIB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Andromeda.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 03 45 ?? 0f be 08 89 4d ?? 8b 55 08 03 55 90 1b 00 8b 45 08 03 45 ?? 8a 08 88 0a 8b 55 08 03 55 90 1b 03 8a 45 90 1b 01 88 02 90 18 8b 45 90 1b 00 83 c0 ?? 89 45 90 1b 00 8b 4d 90 1b 03 83 e9 ?? 89 4d 90 1b 03 8b 55 90 1b 00 3b 55 90 1b 03 7d 29 } //1
		$a_02_1 = {8b 55 08 0f be 02 85 c0 74 ?? 8b 4d 08 8a 11 80 c2 ?? 8b 45 08 88 10 90 18 8b 4d 08 83 c1 01 89 4d 08 } //1
		$a_02_2 = {0f b6 11 33 55 ?? 03 55 ?? a1 ?? ?? ?? ?? 03 45 ?? 88 10 90 18 8b 55 90 1b 03 83 c2 01 89 55 90 1b 03 8b 45 90 1b 03 3b 05 ?? ?? ?? ?? 73 ?? 8b 0d 90 1b 02 03 4d 90 1b 03 0f b6 11 33 55 90 1b 00 03 55 90 1b 01 a1 90 1b 02 03 45 90 1b 03 88 10 eb ?? ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}