
rule TrojanDownloader_Win64_Rugmi_HNAA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 41 56 41 57 [0-40] 48 63 c7 49 8b cf 48 69 f0 8a 00 00 00 } //5
		$a_03_1 = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 41 56 41 57 [0-40] 4c 8b 44 24 60 49 8b cf 48 63 c3 48 69 d0 8a 00 00 00 48 03 d6 e8 } //5
		$a_01_2 = {48 63 41 3c 4d 8b f8 44 8b e2 48 8b f9 44 8b 8c 08 88 00 00 00 41 8b 74 09 20 45 8b 74 09 1c 48 03 f1 41 8b 6c 09 24 4c 03 f1 48 03 e9 8b 1e 48 03 d9 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5) >=5
 
}