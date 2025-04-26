
rule Trojan_Win32_Emotet_SK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4f 23 77 77 23 50 23 23 23 23 23 23 23 77 4f } //1 O#ww#P#######wO
		$a_81_1 = {59 55 51 39 46 2a 6d 69 4f 71 } //1 YUQ9F*miOq
		$a_81_2 = {36 21 68 40 4a 30 56 69 23 4f } //1 6!h@J0Vi#O
		$a_81_3 = {6e 69 37 3d 38 68 4c 4f 36 6f } //1 ni7=8hLO6o
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Emotet_SK_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {eb 00 8b 55 ?? 3b 15 ?? ?? ?? ?? 72 02 eb 42 8b 45 ?? 89 45 ?? c7 45 ?? ?? ?? ?? ?? 8b 4d ?? 03 4d ?? c6 01 00 c7 45 ?? 00 00 00 00 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8a 08 88 0a c7 45 ?? ?? ?? ?? ?? 8b 55 ?? 83 c2 01 89 55 ?? e9 ?? ff ff ff 8b e5 5d c3 } //2
		$a_02_1 = {55 8b ec 81 ec b0 00 00 00 c7 45 ?? 40 00 00 00 c7 45 ?? 00 00 00 00 a1 ?? ?? ?? ?? 89 45 ?? c7 45 ?? ff ff ff ff c6 45 ?? 0d 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ff 75 ?? 68 00 30 00 00 8b 45 ?? 50 ff 75 ?? ff 35 ?? ?? ?? ?? 59 a1 ?? ?? ?? ?? ff d0 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}