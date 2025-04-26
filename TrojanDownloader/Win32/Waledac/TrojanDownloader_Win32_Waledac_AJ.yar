
rule TrojanDownloader_Win32_Waledac_AJ{
	meta:
		description = "TrojanDownloader:Win32/Waledac.AJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {c7 04 24 00 00 20 00 e8 ?? ?? ff ff a3 ?? ?? ?? ?? c7 04 24 00 90 } //1
		$a_03_1 = {83 7c 24 10 03 7d 0c 68 ?? ?? ?? ?? 8d 44 24 28 50 ff d6 ff 44 24 10 c1 6c 24 14 08 83 7c 24 10 04 7c } //1
		$a_03_2 = {8d 42 01 33 d2 f7 74 24 18 39 1c 95 ?? ?? ?? ?? 74 ?? 8d 04 95 ?? ?? ?? ?? 8b 08 89 18 88 5c 24 24 33 c0 8d 7c 24 25 } //1
		$a_02_3 = {2f 31 2e 30 0d 0a [0-10] 74 65 6d 70 00 } //1
		$a_03_4 = {50 ff d6 e8 ?? ?? ?? ?? 8b c8 33 c0 33 db 88 5d f0 8d 7d f1 ab ab 66 ab aa 6a 0b 8d 45 f0 50 51 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_02_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}