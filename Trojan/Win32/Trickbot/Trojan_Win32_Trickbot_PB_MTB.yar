
rule Trojan_Win32_Trickbot_PB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {54 72 39 6a 6e 58 79 35 52 23 4b 7b 71 7a 6b } //1 Tr9jnXy5R#K{qzk
		$a_00_1 = {64 75 7a 24 45 23 6b 51 25 65 74 49 71 30 46 2a 39 55 4e 76 48 66 46 72 4d 51 } //1 duz$E#kQ%etIq0F*9UNvHfFrMQ
		$a_02_2 = {8a 00 88 c1 8b 45 ?? 8b 9c ?? ?? ?? ?? ?? 8b 45 ?? 8b 84 ?? ?? ?? ?? ?? 01 d8 25 ff 00 00 80 85 c0 79 ?? 48 0d 00 ff ff ff 40 8b 84 ?? ?? ?? ?? ?? 31 c8 88 02 ff 45 ?? 8b 45 ?? 3b 45 ?? 0f 92 c0 84 c0 0f 85 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_PB_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 c7 45 ?? 00 00 00 00 eb ?? 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 3b 4d ?? 74 ?? 8b 45 ?? 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 45 ?? 03 45 ?? 8b 4d ?? 8a 00 32 04 11 8b 4d ?? 03 4d ?? 88 01 eb } //1
		$a_02_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-40] 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}