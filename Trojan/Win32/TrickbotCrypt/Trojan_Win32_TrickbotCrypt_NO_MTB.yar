
rule Trojan_Win32_TrickbotCrypt_NO_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0f 81 e2 ff 00 00 00 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 8b ea 8b 54 24 ?? 8a 14 10 32 14 29 8b 6c 24 ?? 88 14 28 a1 ?? ?? ?? ?? 40 3b c3 a3 ?? ?? ?? ?? 72 } //1
		$a_03_1 = {33 d2 8a 14 ?? 8b c3 25 ff 00 00 00 03 ea 03 c5 33 d2 f7 35 ?? ?? ?? ?? 46 47 8b ea 8a 04 29 88 1c 29 88 47 ?? a1 ?? ?? ?? ?? 3b f0 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_TrickbotCrypt_NO_MTB_2{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec ?? 8b 45 ?? 89 45 ?? 8b 4d ?? 89 4d ?? c7 45 f4 00 00 00 00 eb 09 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 3b 45 ?? 73 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 03 55 ?? 8a 02 88 01 eb ?? 8b e5 5d c3 } //1
		$a_03_1 = {0f b7 4a 14 8d 54 08 ?? 89 55 ?? c7 45 ?? 00 00 00 00 eb ?? 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 83 c1 28 89 4d ?? 8b 55 ?? 8b 02 0f b7 48 06 39 4d ?? 0f 8d } //1
		$a_03_2 = {8b 55 f0 83 c2 01 89 55 ?? 8b 45 ?? 83 c0 02 89 45 ?? 8b 4d ?? 8b 51 ?? 83 ea 08 d1 ea 39 55 f0 73 ?? 8b 45 ?? 0f b7 08 c1 f9 0c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}