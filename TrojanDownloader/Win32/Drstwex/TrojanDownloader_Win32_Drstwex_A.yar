
rule TrojanDownloader_Win32_Drstwex_A{
	meta:
		description = "TrojanDownloader:Win32/Drstwex.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 53 05 75 0d 00 00 81 e8 01 00 00 00 c1 e3 02 } //1
		$a_01_1 = {50 53 05 75 0d 00 00 48 c1 e3 02 } //1
		$a_01_2 = {90 90 8a 1e 90 90 90 32 d8 90 88 1e } //5
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //5 WaitForSingleObject
		$a_01_4 = {43 72 65 61 74 65 54 68 72 65 61 64 } //5 CreateThread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=16
 
}
rule TrojanDownloader_Win32_Drstwex_A_2{
	meta:
		description = "TrojanDownloader:Win32/Drstwex.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 0c 8b 55 08 e8 0b 00 00 00 30 02 42 e2 f6 } //1
		$a_03_1 = {83 f8 00 0f 85 f8 00 00 00 6a 00 6a ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 } //1
		$a_03_2 = {68 52 02 00 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 05 ff 00 00 00 a3 ?? ?? ?? ?? 05 ff 00 00 00 a3 ?? ?? ?? ?? 83 c0 44 } //1
		$a_03_3 = {8b 44 24 10 [0-05] c7 00 c3 ?? ?? ?? b8 00 00 00 00 c3 } //1
		$a_03_4 = {8b 00 8b d0 c1 e0 03 33 c2 05 ?? ?? ?? ?? 5a 89 02 c1 e8 18 5a c3 } //1
		$a_03_5 = {6a 00 6a 07 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 ?? 50 8d 45 ?? 50 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 7d ?? 8b 07 } //1
		$a_03_6 = {50 6a 07 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 f8 50 8d 45 fc 50 } //1
		$a_03_7 = {89 45 fc 6a 00 68 00 04 00 00 ff 75 fc ff 75 08 e8 ?? ?? ?? ?? 83 f8 00 74 59 83 f8 ff 74 4b 89 45 f8 03 45 f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1) >=3
 
}