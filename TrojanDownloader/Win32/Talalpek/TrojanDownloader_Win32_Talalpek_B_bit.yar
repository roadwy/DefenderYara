
rule TrojanDownloader_Win32_Talalpek_B_bit{
	meta:
		description = "TrojanDownloader:Win32/Talalpek.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 75 fc ff 35 ?? ?? ?? 10 ff 75 ?? ff 75 f4 ff 35 ?? ?? ?? 10 8f 05 ?? ?? ?? 10 ff 15 ?? ?? ?? 10 89 45 f0 8b 45 f0 8b e5 5d c3 } //1
		$a_03_1 = {8b 4d ec 03 4d e4 8b 55 f4 03 55 e4 8a 02 88 01 c7 45 ?? ?? ?? 00 00 8b 4d f8 83 c1 01 89 4d f8 eb be } //1
		$a_03_2 = {8b 55 f8 8b 02 33 85 ?? ?? ?? ff 8b 4d f8 89 01 8b e5 5d c3 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}