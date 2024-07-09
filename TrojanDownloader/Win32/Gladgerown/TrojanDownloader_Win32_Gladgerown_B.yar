
rule TrojanDownloader_Win32_Gladgerown_B{
	meta:
		description = "TrojanDownloader:Win32/Gladgerown.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 09 8b 55 ?? 83 ea 04 89 55 ?? 8b 45 ?? 3b 45 ?? 72 12 8b 4d ?? 8b 11 81 f2 ?? ?? ?? ?? 8b 45 ?? 89 10 eb dd } //2
		$a_03_1 = {33 d0 8b 45 ?? 03 45 ?? 88 10 8b 4d ?? 83 c1 01 89 4d ?? 8b 55 ?? 3b 55 ?? 75 07 } //1
		$a_02_2 = {25 30 38 78 00 [0-07] 25 73 5f 25 78 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}