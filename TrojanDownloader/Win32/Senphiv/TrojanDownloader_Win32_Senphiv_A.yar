
rule TrojanDownloader_Win32_Senphiv_A{
	meta:
		description = "TrojanDownloader:Win32/Senphiv.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 00 3f 00 ?? 6a 74 68 00 01 00 00 ?? e8 ?? ?? ff ff e8 ?? ?? ff ff 68 ?? ?? ?? ?? eb 09 } //1
		$a_03_1 = {66 b9 59 00 e8 ?? ?? ?? ?? 8b 4d ?? 88 01 66 b9 58 00 } //1
		$a_01_2 = {00 6d 43 68 61 6e 67 65 49 45 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}