
rule TrojanDownloader_Win32_Adload_DU_bit{
	meta:
		description = "TrojanDownloader:Win32/Adload.DU!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fd 9a 80 5c 49 4e 65 74 43 2e 64 6c 6c 00 2f 45 4e 44 00 68 74 74 70 3a 2f 2f 77 77 77 2e 70 61 70 61 70 69 6e 67 2e 63 6f 6d } //1
		$a_01_1 = {00 2f 75 73 65 72 61 67 65 6e 74 00 2f 4e 4f 50 52 4f 58 59 00 67 65 74 00 4f 4b 00 } //1 ⼀獵牥条湥t丯偏佒奘最瑥伀K
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Adload_DU_bit_2{
	meta:
		description = "TrojanDownloader:Win32/Adload.DU!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 1c 8b 00 8b 40 08 a3 ?? ?? ?? 00 8d 45 fc ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 45 f8 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 4d ?? 8b 55 fc 8b 45 f8 e8 ?? ?? ?? ff } //1
		$a_01_1 = {8b 55 fc 8b 55 f8 8a 54 32 ff 32 da 88 5c 30 ff 46 4f 75 90 } //1
		$a_03_2 = {6a 05 6a 00 8b 03 e8 ?? ?? ?? ff 50 8d 85 ?? ff ff ff 8b 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 85 ?? ff ff ff e8 ?? ?? ?? ff 50 68 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}