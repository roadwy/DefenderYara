
rule Trojan_Win32_Stealer_SIBB_MTB{
	meta:
		description = "Trojan:Win32/Stealer.SIBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 06 01 00 00 00 8d 8d ?? ?? ?? ?? ba ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 38 ff 57 ?? 8b 85 90 1b 00 8b 16 0f b6 7c 10 ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 2b d0 52 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5a 92 8b ca 99 f7 f9 03 fa 8b d7 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 95 90 1b 0a b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 06 ff 4d ?? 75 } //1
		$a_03_1 = {0f b7 70 06 4e 85 f6 7c ?? 46 33 db [0-20] 48 0f af ca 8d 04 9b 8b 55 ?? 8b 7c c2 08 31 d8 89 ca 8d 04 9b 8b 55 90 1b 02 8b 44 c2 10 89 45 ?? 50 [0-0a] 6a 04 68 00 10 00 00 57 8d 04 9b 8b 55 90 1b 02 8b 44 c2 0c 03 45 ?? 50 e8 ?? ?? ?? ?? 89 45 ?? [0-0a] 8d 04 9b 8b 55 90 1b 02 8b 44 c2 14 03 45 b0 8b 55 90 1b 09 8b 4d 90 1b 04 e8 ?? ?? ?? ?? 43 4e 75 } //1
		$a_03_2 = {83 e8 08 d1 e8 8b 55 08 89 42 ?? 8b 45 08 8b 40 ?? 83 c0 08 89 03 [0-05] 8b 45 08 8b 50 90 1b 00 4a 85 d2 72 ?? 42 [0-05] 8b 03 66 8b 00 f6 c4 f9 74 ?? 8b 4d 08 8b 49 ?? 8b 75 08 8b 76 90 1b 01 03 0e 66 25 ff 0f 0f b7 c0 03 c8 8b 45 08 8b 40 ?? 01 01 83 03 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}