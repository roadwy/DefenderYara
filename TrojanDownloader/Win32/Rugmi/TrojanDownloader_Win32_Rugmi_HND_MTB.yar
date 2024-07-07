
rule TrojanDownloader_Win32_Rugmi_HND_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 03 8b 00 8b 55 08 03 42 e4 83 c0 02 8b 55 08 89 42 cc 8b 45 08 8b 40 cc 50 8b 07 50 ff } //1
		$a_01_1 = {8b 45 fc 83 c0 02 8d 14 85 00 00 00 00 8b 45 f8 01 d0 8b 08 8b 45 fc 8d 14 85 00 00 00 00 8b 45 0c 01 d0 8b 55 f0 01 ca 89 10 83 45 fc 01 eb c8 } //1
		$a_01_2 = {8b 45 08 8d 55 e0 c7 44 24 0c 08 00 00 00 8b 4d 0c 89 54 24 08 29 d8 43 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}