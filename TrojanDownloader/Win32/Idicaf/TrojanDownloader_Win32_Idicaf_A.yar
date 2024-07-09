
rule TrojanDownloader_Win32_Idicaf_A{
	meta:
		description = "TrojanDownloader:Win32/Idicaf.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a 08 84 c9 74 08 80 f1 ?? 88 08 40 eb f2 } //2
		$a_01_1 = {e9 b6 00 00 00 8b 4d f8 8b 51 01 89 55 e0 8b 45 e0 8b 4d f8 8d 54 01 05 89 55 d8 8b 45 d8 3b 45 0c 74 0f } //2
		$a_03_2 = {76 17 6a 19 53 e8 ?? ?? ff ff 8a 44 05 e0 59 88 04 3e 46 3b 75 0c 59 72 e9 } //1
		$a_01_3 = {44 65 74 6f 75 72 44 6c 6c 2e 64 6c 6c 00 49 6e 69 74 00 } //1
		$a_01_4 = {52 6f 6f 74 23 52 43 56 59 4c 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}