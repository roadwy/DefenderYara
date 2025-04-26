
rule TrojanDownloader_Win32_Zirit_A{
	meta:
		description = "TrojanDownloader:Win32/Zirit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c2 28 8b 02 03 05 ?? ?? ?? 00 c7 44 24 28 ?? ?? ?? 00 ff e0 61 6a 00 ff 15 ?? ?? ?? 00 } //1
		$a_03_1 = {b9 03 00 00 00 8b 06 35 0d 0d 0d 0d 89 06 83 c6 04 e2 f2 be ?? ?? ?? 00 b9 0c 00 00 00 f3 a4 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 68 ?? ?? ?? 00 } //1
		$a_03_2 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 a3 ?? ?? ?? 00 6a 02 6a 00 6a fc ff 35 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}